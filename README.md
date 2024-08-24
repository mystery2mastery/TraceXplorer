# TraceXplorer

TraceXplorer is a dynamic malware analysis tool written using Frida-Python DBI (Dynamic Binary Instrumentation) Framework.

## How to use:

1. Install frida for python:

   ```cmd
   cmd> pip install frida-tools
   ```
2. Set the frida logging options in *frida_settings.ini* file.

3. Execute the program and collect the logs using:

   ```cmd
   cmd> python start.py "C:\windows\system32\notepad.exe"
   ```

   ```cmd
   cmd> python start.py "C:\windows\system32\rundll32.exe" "path\to\some.dll",someexport
   ```
4. Press `Ctrl+C` to stop the execution of the process and save the logs. Sometimes the script fails to terminate the process after .log file generation, in such cases you need to manually terminate the process.

## Log options:

We can log basic block trace, calls, jmps, syscalls, win32 APIs etc.

Adjust the *frida_settings.ini* to log what you need.

As of now, the intercepted API content is logged to the command window instead of a file. In future, I will modify it to log everything to a file so that it can be imported into IDA Pro for further analysis.

Example output files when calc.exe is executed are provided in *test_output* folder.
