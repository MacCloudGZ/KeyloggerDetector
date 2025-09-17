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
public class KDetector {
    // Set to true to enable debug output
    private static final boolean DEBUGGING = false;
    // Add interpreters to check for script-based keyloggers
    private static final String[] INTERPRETER_NAMES = {"python", "python3", "perl", "ruby", "php", "bash", "sh", "node"};
    private static final String[] USER_DIRS = {"/home", "/tmp", "/var/tmp"};
    /** Get the current process PID as a String */
    private static String getOwnPid() {
        String pid = "";
        try {
            String jvmName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
            int at = jvmName.indexOf('@');
            if (at > 0) {
                pid = jvmName.substring(0, at);
            }
        } catch (Exception ignored) {}
        return pid;
    }

    private static final String[] SUSPICIOUS_PATTERNS = {
        "keylog", "logkeys", "keylogger", "key-logger", "pykey", "klogger",
        "klg", "hook", "spy", "xinput", "evdev"
    };

    private static final String[] SEARCH_PATHS = {
        "/usr/bin", "/usr/local/bin", "/opt", "/tmp", "/var/tmp", "/etc", "/home"
    };

    public static void main(String[] args) {
        System.out.println("=== Keylogger Detector (Java) ===");
        try (Scanner sc = new Scanner(System.in)) {
            System.out.print("Open console and proceed with sudo checks? (y/N): ");
            String ans = sc.nextLine().trim().toLowerCase();
            if (!ans.equals("y") && !ans.equals("yes")) {
                System.out.println("End program");
                return;
            }

            if (!validateSudo()) {
                System.out.println("Sudo validation failed or cancelled. End program");
                return;
            }

            // Step 1: Check for keylogger
            DetectionResult result = detectIndicators();
            List<ProcessMatch> interpreterMatches = detectInterpreterScripts();
            // Debug note: print if any process is using python pyinput
            for (ProcessMatch pm : interpreterMatches) {
                if (pm.rawLine.toLowerCase().contains("python") && pm.rawLine.toLowerCase().contains("pyinput")) {
                    if(DEBUGGING) System.out.println("[DEBUG] Found interpreter-based pyinput process: " + pm.rawLine);
                }
            }
            // Check for 'pyinput' process and auto-kill/purge if found
            boolean pyinputFound = false;
            List<ProcessMatch> pyinputMatches = new ArrayList<>();
            // Check in interpreter-based matches
            for (ProcessMatch pm : interpreterMatches) {
                if (pm.rawLine.toLowerCase().contains("pyinput")) {
                    pyinputFound = true;
                    pyinputMatches.add(pm);
                }
            }
            if (pyinputFound) {
                System.out.println("[!] pyinput keylogger detected! Attempting to terminate and purge...");
                attemptKillInterpreter(pyinputMatches);
                attemptPurge(result);
                System.out.println("[!] pyinput keylogger terminated and purged (if possible). Continuing with normal flow...");
            } else if (DEBUGGING) {
                System.out.println("[DEBUG] No active pyinput process detected.");
            }
            boolean foundKeylogger = result.hasAny() || !interpreterMatches.isEmpty();

            if (foundKeylogger) {
                System.out.println("\n=== Keylogger found ===");
                if (result.hasAny()) result.printSummary();
                if (!interpreterMatches.isEmpty()) {
                    System.out.println("Interpreter-based suspicious scripts:");
                    for (ProcessMatch pm : interpreterMatches) {
                        System.out.println("    " + pm.rawLine);
                    }
                }

                // Show keylogger directory (if any file or script found)
                Set<String> dirs = new HashSet<>();
                for (String f : result.fileMatches) {
                    File ff = new File(f);
                    dirs.add(ff.getParent());
                }
                for (ProcessMatch pm : interpreterMatches) {
                    String[] cols = pm.rawLine.trim().split("\\s+");
                    if (cols.length > 10) {
                        String scriptPath = cols[10];
                        File ff = new File(scriptPath);
                        dirs.add(ff.getParent());
                    }
                }
                if (!dirs.isEmpty()) {
                    System.out.println("Keylogger directory/directories:");
                    for (String d : dirs) System.out.println("    " + d);
                }

                // Show if there's active keylogger (always true if found)
                System.out.println("Active keylogger detected.");

                // Ask: do you want to terminate/stop the active keylogger?
                if (askYesNo(sc, "Do you want to terminate/stop the active keylogger? (y/N): ")) {
                    boolean terminated = attemptPurge(result) | attemptKillInterpreter(interpreterMatches);
                    if (terminated) {
                        System.out.println("Show that active keylogger filelocation:");
                        for (String d : dirs) System.out.println("    " + d);
                        boolean purged = attemptPurge(result);
                        if (purged) {
                            System.out.println("Output success");
                        } else {
                            System.out.println("Output error");
                            boolean retry = askYesNo(sc, "Retry using alternate purge methods? (y/N): ");
                            if (retry) {
                                if (attemptAlternatePurge(result)) {
                                    System.out.println("Alternate purge succeeded.");
                                } else {
                                    System.out.println("Alternate purge failed. Return to Purge active keylogger.");
                                }
                            } else {
                                System.out.println("Return to Purge active keylogger.");
                            }
                        }
                    } else {
                        System.out.println("Try another method to terminate the active program. Return to terminate program.");
                    }
                } else {
                    System.out.println("Remove the active keylogger to the keylogger remove list;");
                }

                // Ask: Do you want to remove the remaining keylogger data?
                if (askYesNo(sc, "Do you want to remove the remaining keylogger data? (y/N): ")) {
                    boolean purged = attemptPurge(result);
                    if (purged) {
                        System.out.println("Output success");
                    } else {
                        System.out.println("Output error");
                        boolean retry = askYesNo(sc, "Retry using alternate purge methods? (y/N): ");
                        if (retry) {
                            if (attemptAlternatePurge(result)) {
                                System.out.println("Alternate purge succeeded.");
                            } else {
                                System.out.println("Alternate purge failed. Return to Purge keylogger.");
                            }
                        } else {
                            System.out.println("Return to Purge keylogger.");
                        }
                    }
                } else {
                    System.out.println("End program");
                }
            } else {
                System.out.println("No keylogger found");
            }
            System.out.println("Pause program. Press ENTER to end program...");
            sc.nextLine();
            System.out.println("End program");
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
        }
    }

    /** Detect interpreter-based suspicious scripts (e.g. python abc.py in /home) */
    private static List<ProcessMatch> detectInterpreterScripts() {
        List<ProcessMatch> matches = new ArrayList<>();
        String ownPid = getOwnPid();
        List<String> ps = runAndCollect(new String[]{"ps", "aux"});
        for (String line : ps) {
            String low = line.toLowerCase();
            for (String interp : INTERPRETER_NAMES) {
                if (low.contains(interp)) {
                    String[] cols = line.trim().split("\\s+");
                    String pid = cols.length > 1 ? cols[1] : "unknown";
                    if (pid.equals(ownPid)) continue;
                    // Try to find script path in command line
                    for (String userDir : USER_DIRS) {
                        for (String arg : cols) {
                            if (arg.startsWith(userDir) && (arg.endsWith(".py") || arg.endsWith(".sh") || arg.endsWith(".pl") || arg.endsWith(".js") || arg.endsWith(".rb") || arg.endsWith(".php"))) {
                                matches.add(new ProcessMatch(pid, line));
                                break;
                            }
                        }
                    }
                }
            }
        }
        return matches;
    }

    /** Attempt to kill interpreter-based suspicious scripts */
    private static boolean attemptKillInterpreter(List<ProcessMatch> matches) {
        boolean allOk = true;
        for (ProcessMatch pm : matches) {
            if (pm.pid.equals("unknown")) {
                allOk = false;
                continue;
            }
            CommandResult killRes = runCommandBlocking(new String[]{"sudo", "kill", "-9", pm.pid}, true);
            if (killRes.exitCode == 0) {
                System.out.println("    [+] Killed interpreter pid " + pm.pid);
            } else {
                System.out.println("    [-] Failed to kill interpreter pid " + pm.pid);
                allOk = false;
            }
        }
        return allOk;
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
    String ownPid = getOwnPid();

        System.out.println("\n[*] Scanning running processes for suspicious names...");
        List<String> ps = runAndCollect(new String[]{"ps", "aux"});
        for (String line : ps) {
            String low = line.toLowerCase();
            for (String pat : SUSPICIOUS_PATTERNS) {
                if (low.contains(pat)) {
                    String[] cols = line.trim().split("\\s+");
                    String pid = cols.length > 1 ? cols[1] : "unknown";
                    // Exclude own process
                    if (!pid.equals(ownPid)) {
                        res.processMatches.add(new ProcessMatch(pid, line));
                    }
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
                if (DEBUGGING) {
                    System.out.println("[DEBUG] Raw lsof output:");
                    for (String l : lsofOut.stdoutLines) {
                        System.out.println("[DEBUG] " + l);
                    }
                }
                for (String l : lsofOut.stdoutLines) {
                    String line = l.trim();
                    if (line.toLowerCase().startsWith("command") || line.isEmpty()) continue;
                    String[] c = line.split("\\s+");
                    String pid = c.length > 1 ? c[1] : "unknown";
                    // Exclude own process
                    if (!pid.equals(ownPid)) {
                        res.lsofMatches.add(new ProcessMatch(pid, line));
                    }
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