import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * KeyloggerDetector.java
 *
 * Interactive console keylogger detector + purge helper for Linux (Java).
 * - Heuristic detection: suspicious process names, lsof /dev/input, suspicious filenames
 * - Interactive purge: kill processes, remove files, disable systemd services, clean crontabs
 *
 * WARNING: Purge actions are destructive. Use in a VM or safe environment.
 */
public class KeyloggerDetector {

    private static final String[] SUSPICIOUS_PATTERNS = {
        "keylog", "logkeys", "keylogger", "key-logger", "pykey", "klogger",
        "klg", "hook", "spy", "xinput", "evdev"
    };

    private static final String[] SEARCH_PATHS = {
        "/usr/bin", "/usr/local/bin", "/opt", "/tmp", "/var/tmp", "/etc", "/home"
    };

    public static void main(String[] args) {
        System.out.println("=== Simple Keylogger Detector (Java) ===");
        try (Scanner sc = new Scanner(System.in)) {
            System.out.print("Open console and proceed with sudo checks? (y/N): ");
            String ans = sc.nextLine().trim().toLowerCase();
            if (!ans.equals("y") && !ans.equals("yes")) {
                System.out.println("Exiting. (No checks performed.)");
                return;
            }

            if (!validateSudo()) {
                System.out.println("Sudo validation failed or cancelled. Exiting.");
                return;
            }

            // Detection
            DetectionResult result = detectIndicators();

            if (result.hasAny()) {
                System.out.println("\n=== Potential keylogger indicators found ===");
                result.printSummary();

                if (askYesNo(sc,
                    "\nDo you want to attempt to purge the detected items? (This will try to kill processes and remove files) (y/N): ")) {

                    while (true) {
                        if (attemptPurge(result)) {
                            System.out.println("[+] Purge completed successfully.");
                            break;
                        } else {
                            System.out.println("[-] Purge either partially failed or some items remain.");
                            boolean tryOther = askYesNo(sc,
                                "Retry purge using alternate methods (disable systemd services, clean crontabs)? (y/N): ");
                            if (!tryOther) {
                                boolean retry = askYesNo(sc, "Do you want to retry the purge again? (y/N): ");
                                if (!retry) {
                                    System.out.println("Giving up purge attempts. You should inspect items manually.");
                                    break;
                                }
                            } else {
                                if (attemptAlternatePurge(result)) {
                                    System.out.println("[+] Alternate purge succeeded.");
                                    break;
                                } else {
                                    System.out.println("[-] Alternate purge failed.");
                                    boolean retry = askYesNo(sc,
                                        "Retry alternate purge or original purge? (y = retry alternate, n = stop): ");
                                    if (!retry) {
                                        System.out.println("Stopping purge attempts.");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    System.out.println("Purge skipped by user. Exiting after pause.");
                }
            } else {
                System.out.println("\n[+] No keylogger indicators found.");
            }

            System.out.println("\nPress ENTER to end program...");
            sc.nextLine();
            System.out.println("Program ended.");
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
        }
    }

    /** Simple yes/no prompt */
    private static boolean askYesNo(Scanner sc, String prompt) {
        System.out.print(prompt);
        String a = sc.nextLine().trim().toLowerCase();
        return a.equals("y") || a.equals("yes");
    }

    /** Validate sudo - ask for password if necessary */
    private static boolean validateSudo() {
        System.out.println("[*] Validating sudo (you may be prompted for your password)...");
        return runCommandBlocking(new String[]{"sudo", "-v"}, true).exitCode == 0;
    }

    /** Detect processes, lsof /dev/input, files */
    private static DetectionResult detectIndicators() {
        DetectionResult res = new DetectionResult();

        System.out.println("\n[*] Scanning running processes for suspicious names...");
        List<String> ps = runAndCollect(new String[]{"ps", "aux"});
        for (String line : ps) {
            String low = line.toLowerCase();
            for (String pat : SUSPICIOUS_PATTERNS) {
                if (low.contains(pat)) {
                    String[] cols = line.trim().split("\\s+");
                    String pid = cols.length > 1 ? cols[1] : "unknown";
                    res.processMatches.add(new ProcessMatch(pid, line));
                    break;
                }
            }
        }
        if (res.processMatches.isEmpty()) {
            System.out.println("[+] No suspicious-named processes found.");
        }

        System.out.println("\n[*] Checking processes that opened /dev/input (requires sudo + lsof)...");
        if (!isInstalled("lsof")) {
            System.out.println("    lsof not found. Skipping /dev/input check. Install lsof to enable this check.");
        } else {
            CommandResult lsofOut = runCommandBlocking(new String[]{"sudo", "lsof", "/dev/input"}, true);
            if (lsofOut.exitCode == 0 && !lsofOut.stdoutLines.isEmpty()) {
                for (String l : lsofOut.stdoutLines) {
                    String line = l.trim();
                    if (line.toLowerCase().startsWith("command") || line.isEmpty()) continue;
                    String[] c = line.split("\\s+");
                    String pid = c.length > 1 ? c[1] : "unknown";
                    res.lsofMatches.add(new ProcessMatch(pid, line));
                }
                if (!res.lsofMatches.isEmpty()) {
                    System.out.println("[!] Processes with /dev/input open:");
                    res.lsofMatches.forEach(pm -> System.out.println("    " + pm.rawLine));
                }
            } else {
                System.out.println("[+] No processes found with /dev/input (or permission issue).");
            }
        }

        System.out.println("\n[*] Searching common directories for suspicious filenames...");
        for (String base : SEARCH_PATHS) {
            File fbase = new File(base);
            if (!fbase.exists()) continue;
            searchFilesRecursive(fbase, res.fileMatches);
        }
        if (res.fileMatches.isEmpty()) {
            System.out.println("[+] No suspicious filenames found in common directories.");
        } else {
            System.out.println("[!] Suspicious files:");
            res.fileMatches.forEach(path -> System.out.println("    " + path));
        }

        return res;
    }

    /** Recursive file search that appends suspicious matches into list */
    private static void searchFilesRecursive(File dir, List<String> outList) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            try {
                if (f.isDirectory()) {
                    if (Files.isSymbolicLink(f.toPath())) continue;
                    searchFilesRecursive(f, outList);
                } else {
                    String name = f.getName().toLowerCase();
                    for (String pat : SUSPICIOUS_PATTERNS) {
                        if (name.contains(pat)) {
                            outList.add(f.getAbsolutePath());
                            break;
                        }
                    }
                }
            } catch (SecurityException ignored) {}
        }
    }

    /** Attempt purge: kill processes, remove files, disable systemd units, clean crontabs */
    private static boolean attemptPurge(DetectionResult res) {
        boolean allOk = true;

        // Kill processes
        Set<String> pids = new LinkedHashSet<>();
        res.processMatches.forEach(pm -> pids.add(pm.pid));
        res.lsofMatches.forEach(pm -> pids.add(pm.pid));

        if (!pids.isEmpty()) {
            System.out.println("\n[*] Killing processes: " + String.join(", ", pids));
            for (String pid : pids) {
                if ("unknown".equals(pid)) {
                    allOk = false;
                    continue;
                }
                CommandResult killRes = runCommandBlocking(new String[]{"sudo", "kill", "-9", pid}, true);
                if (killRes.exitCode == 0) {
                    System.out.println("    [+] Killed pid " + pid);
                } else {
                    System.out.println("    [-] Failed to kill pid " + pid);
                    allOk = false;
                }
            }
        }

        // Remove files
        if (!res.fileMatches.isEmpty()) {
            System.out.println("\n[*] Removing suspicious files...");
            for (String path : res.fileMatches) {
                CommandResult rm = runCommandBlocking(new String[]{"sudo", "rm", "-f", path}, true);
                if (rm.exitCode == 0) {
                    System.out.println("    [+] Removed: " + path);
                } else {
                    System.out.println("    [-] Failed to remove: " + path);
                    allOk = false;
                }
            }
        }

        // Disable systemd units
        List<String> suspiciousUnits = findSuspiciousSystemdUnits();
        if (!suspiciousUnits.isEmpty()) {
            System.out.println("\n[*] Disabling suspicious systemd services:");
            for (String unit : suspiciousUnits) {
                CommandResult dis = runCommandBlocking(new String[]{"sudo", "systemctl", "disable", "--now", unit}, true);
                if (dis.exitCode == 0) {
                    System.out.println("    [+] Disabled: " + unit);
                } else {
                    System.out.println("    [-] Could not disable: " + unit);
                    allOk = false;
                }
            }
        }

        // Clean crontabs
        if (!cleanCrontabs()) {
            System.out.println("    [-] Some crontab cleaning failed.");
            allOk = false;
        }

        DetectionResult after = detectIndicators();
        if (after.hasAny()) {
            System.out.println("\n[!] Some indicators still present after purge.");
            after.printSummary();
            return false;
        }
        return allOk;
    }

    /** Alternate purge: extra attempts */
    private static boolean attemptAlternatePurge(DetectionResult res) {
        boolean ok = true;
        List<String> suspiciousUnits = findSuspiciousSystemdUnits();
        for (String unit : suspiciousUnits) {
            if (runCommandBlocking(new String[]{"sudo", "systemctl", "stop", unit}, true).exitCode != 0) ok = false;
            if (runCommandBlocking(new String[]{"sudo", "systemctl", "disable", unit}, true).exitCode != 0) ok = false;
        }
        for (String path : res.fileMatches) {
            if (runCommandBlocking(new String[]{"sudo", "rm", "-f", path}, true).exitCode != 0) ok = false;
        }
        if (!cleanCrontabs()) ok = false;

        DetectionResult after = detectIndicators();
        if (after.hasAny()) {
            System.out.println("\n[!] Alternate purge did not remove all indicators.");
            after.printSummary();
            return false;
        }
        return ok;
    }

    /** Find systemd units whose names match suspicious patterns */
    private static List<String> findSuspiciousSystemdUnits() {
        List<String> matches = new ArrayList<>();
        if (!isInstalled("systemctl")) return matches;
        CommandResult out = runCommandBlocking(
            new String[]{"systemctl", "list-unit-files", "--type=service", "--no-pager"}, false);
        for (String line : out.stdoutLines) {
            for (String pat : SUSPICIOUS_PATTERNS) {
                if (line.toLowerCase().contains(pat)) {
                    String[] cols = line.trim().split("\\s+");
                    if (cols.length > 0) matches.add(cols[0]);
                    break;
                }
            }
        }
        return matches;
    }

    /** Clean suspicious cron entries */
    private static boolean cleanCrontabs() {
        boolean ok = true;
        List<Path> toCheck = new ArrayList<>();
        Path etcCrontab = Paths.get("/etc/crontab");
        if (Files.exists(etcCrontab)) toCheck.add(etcCrontab);
        Path cronD = Paths.get("/etc/cron.d");
        if (Files.exists(cronD) && Files.isDirectory(cronD)) {
            try {
                Files.walk(cronD, 1).filter(Files::isRegularFile).forEach(toCheck::add);
            } catch (IOException ignored) {}
        }
        Path spool1 = Paths.get("/var/spool/cron/crontabs");
        Path spool2 = Paths.get("/var/spool/cron");
        if (Files.exists(spool1) && Files.isDirectory(spool1)) {
            try {
                Files.walk(spool1, 1).filter(Files::isRegularFile).forEach(toCheck::add);
            } catch (IOException ignored) {}
        } else if (Files.exists(spool2) && Files.isDirectory(spool2)) {
            try {
                Files.walk(spool2, 1).filter(Files::isRegularFile).forEach(toCheck::add);
            } catch (IOException ignored) {}
        }

        for (Path p : toCheck) {
            try {
                List<String> lines = Files.readAllLines(p);
                List<String> filtered = lines.stream()
                        .filter(line -> {
                            String low = line.toLowerCase();
                            for (String pat : SUSPICIOUS_PATTERNS) {
                                if (low.contains(pat)) return false;
                            }
                            return true;
                        }).collect(Collectors.toList());
                if (filtered.size() != lines.size()) {
                    Path bak = p.resolveSibling(p.getFileName().toString() + ".bak." + System.currentTimeMillis());
                    Files.copy(p, bak, StandardCopyOption.REPLACE_EXISTING);
                    Files.write(p, filtered, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                    System.out.println("    [+] Cleaned crontab file: " + p + " (backup at " + bak + ")");
                }
            } catch (IOException ioe) {
                System.out.println("    [-] Could not modify crontab: " + p + " (" + ioe.getMessage() + ")");
                ok = false;
            }
        }
        return ok;
    }

    /** Utility: check if a binary is installed */
    private static boolean isInstalled(String prog) {
        CommandResult r = runCommandBlocking(new String[]{"which", prog}, false);
        return r.exitCode == 0 && !r.stdoutLines.isEmpty();
    }

    /** Run command helper */
    private static CommandResult runCommandBlocking(String[] cmd, boolean inheritStdio) {
        List<String> stdout = new ArrayList<>();
        int code = -1;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            if (inheritStdio) {
                pb.inheritIO();
                Process p = pb.start();
                code = p.waitFor();
                return new CommandResult(code, stdout);
            } else {
                pb.redirectErrorStream(true);
                Process p = pb.start();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        stdout.add(line);
                    }
                }
                code = p.waitFor();
            }
        } catch (IOException | InterruptedException ignored) {}
        return new CommandResult(code, stdout);
    }

    private static List<String> runAndCollect(String[] cmd) {
        return runCommandBlocking(cmd, false).stdoutLines;
    }

    private static class CommandResult {
        int exitCode;
        List<String> stdoutLines;
        CommandResult(int code, List<String> lines) {
            this.exitCode = code;
            this.stdoutLines = lines == null ? Collections.emptyList() : lines;
        }
    }

    private static class DetectionResult {
        List<ProcessMatch> processMatches = new ArrayList<>();
        List<ProcessMatch> lsofMatches = new ArrayList<>();
        List<String> fileMatches = new ArrayList<>();

        boolean hasAny() {
            return !processMatches.isEmpty() || !lsofMatches.isEmpty() || !fileMatches.isEmpty();
        }

        void printSummary() {
            if (!processMatches.isEmpty()) {
                System.out.println("Processes matching suspicious names:");
                processMatches.forEach(pm -> System.out.println("    " + pm.rawLine));
            }
            if (!lsofMatches.isEmpty()) {
                System.out.println("Processes using /dev/input:");
                lsofMatches.forEach(pm -> System.out.println("    " + pm.rawLine));
            }
            if (!fileMatches.isEmpty()) {
                System.out.println("Suspicious files:");
                fileMatches.forEach(p -> System.out.println("    " + p));
            }
        }
    }

    private static class ProcessMatch {
        String pid;
        String rawLine;
        ProcessMatch(String pid, String rawLine) {
            this.pid = pid;
            this.rawLine = rawLine;
        }
    }
}
