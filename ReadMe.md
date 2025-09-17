# Keylogger Detector (Java, Linux)

A console-based **keylogger detector and remover** written in Java.  
Runs inside the Linux terminal and uses `sudo` for privileged operations.  
Best used in a **virtual machine** (VM) for safety and testing.

---


## Features
- ✅ Asks for sudo permission before scanning
- ✅ Detects suspicious **processes** by name patterns
- ✅ Detects **interpreter-based keyloggers** (e.g., Python, Bash, Node.js scripts) running from user directories, even with generic filenames
- ✅ Uses `lsof /dev/input` to detect processes monitoring keyboard input
- ✅ Searches **common directories** for suspicious filenames
- ✅ Interactive **purge option**:
    - Kills suspicious processes
    - Kills interpreter-based suspicious scripts
    - Removes suspicious files
    - Disables suspicious `systemd` services
    - Cleans suspicious `cron` jobs
- ✅ Retry with alternate purge methods if needed
- ✅ Safe **pause before exit**

---

## Program Flow
```text
Start program
Open console
Ask for sudo password
If yes:
    Checks if there's a keylogger currently running
    Finds the keylogger directory
    If keylogger found:
        Show keylogger found
        Show keylogger directory
        Show if there's active keylogger
        Ask: do you want to terminate/stop the active keylogger?
        if yes:
            terminate the program:
            if terminate success:
                Show that active keylogger filelocation;
                Purge that active keylogger:
                If purge successful:
                    Output success
                Else:
                    Output error
                    Retry using alternate purge methods
                    Return to Purge active keylogger
            Else:
                try another method to terminate the active program:
                Return to terminate program
        Else:
            Remove the active keylogger to the keylogger remove list;

        Ask: Do you want to remove the remaining keylogger data?
        if yes:
            Purge keylogger:
            If purge successful:
                Output success
            Else:
                Output error
               Retry using alternate purge methods
                Return to Purge keylogger
        Else:
            end program
    Else:
         No keylogger found
    Pause program
    End program
If no:
    End program
```
---

## Requirements

* Java 8+ (JDK)
* `lsof` recommended for `/dev/input` checks (optional)
* Run inside a VM or safely isolated environment for testing

---

## Compile & Run (Linux)

1. Save the Java source as `KeyloggerDetector.java`.

2. Compile:

```bash
javac KeyloggerDetector.java
```

3. Run:

```bash
java KeyloggerDetector
```

You will be prompted whether to proceed. If you confirm, the program will run `sudo -v` to validate privileges and then perform the checks.

---


## Output & What to look for

* **Processes:** Lines printed from `ps aux` that match suspicious name patterns (e.g., `keylog`, `keylogger`, `logkeys`, etc.).
* **Interpreter-based scripts:** Any process running a script (e.g., `.py`, `.sh`, `.js`, etc.) from user directories (like `/home`, `/tmp`, `/var/tmp`), regardless of the script's filename. This helps catch disguised or generically-named keyloggers.
* **/dev/input usage:** Output from `lsof /dev/input` (requires `lsof` and `sudo`). User processes holding `/dev/input/event*` are suspicious.
* **Files:** Any files in common system and user directories whose names match suspicious patterns.

If any indicators are found, the program prints them and summarizes at the end, following the interactive flow described above.

---


## Limitations & Safety Notes

* This is a **heuristic** scanner. It will produce false positives and cannot find every keylogger (especially kernel-level rootkits or highly stealthy malware).
* Interpreter/script-based detection will flag any script running from user directories, even if the filename is generic (e.g., `abc.py`). This may include legitimate scripts, so review findings before purging.
* Use additional tools for deeper analysis: `chkrootkit`, `rkhunter`, offline disk inspection with a rescue image, or integrity tools like Tripwire.
* Running destructive actions (killing processes, deleting files) is intentionally left manual so you can inspect findings before taking action.
* Because the program uses `sudo`, ensure you run it in an environment you control (VM recommended).

---

## Extending the Program

Ideas you can add:

* Systemd service and crontab checks for persistent units/jobs
* Hash-based whitelist/blacklist checks (MD5/SHA256)
* JSON output for automated parsing and alerting
* Option to quarantine suspicious files (use with caution)

---

## License

This project is provided as-is for educational and defensive purposes. No warranty. Use at your own risk.

---

## Contact

If you want modifications (e.g., add systemd/crontab checks or JSON output), tell me what to add and I’ll update the code and README.
