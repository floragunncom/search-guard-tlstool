@echo off
set SCRIPT_DIR=%~dp0
"%JAVA_HOME%\bin\java" -cp "%SCRIPT_DIR%\..\deps\*" com.floragunn.searchguard.tools.tlsdiag.SearchGuardTlsDiagnosis %*
