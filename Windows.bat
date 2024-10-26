@echo off
setlocal enabledelayedexpansion
net session

if %errorlevel%==0 (
	echo Admin rights granted!
) else (
    echo Failure, no rights - run in Admin mode
	pause
    exit
)

:menu
	cls
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo ".____    .__  __    __  .__           __________      ___.  ___.           ___________     ___.   .__                       "
    echo "|    |   |__|/  |__/  |_|  |   ____   \______   \ ____\_ |__\_ |__ ___.__. \__    ___/____ \_ |__ |  |   ____   ______      "
    echo "|    |   |  \   __\   __\  | _/ __ \   |    |  _//  _ \| __ \| __ <   |  |   |    |  \__  \ | __ \|  | _/ __ \ /  ___/      "
    echo "|    |___|  ||  |  |  | |  |_\  ___/   |    |   (  <_> ) \_\ \ \_\ \___  |   |    |   / __ \| \_\ \  |_\  ___/ \___ \       "
    echo "|_______ \__||__|  |__| |____/\___  >  |______  /\____/|___  /___  / ____|   |____|  (____  /___  /____/\___  >____  >      "
    echo "        \/                        \/          \/           \/    \/\/                     \/    \/          \/     \/       "
    echo "                                                                                                                            "
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Written by: William Tipton~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~<3~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "1) Enable Firewall           2) Correct Policy Settings                                                                     "
    echo "3) Services                  4) Disable Remote Connections                                                                  "
    echo "5) Create Group              6) User Management                                                                             "
    echo "                                                                                                                            "
    echo "                               -1) Exit                        69) Reboot                                                   "
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    pause


	set /p answer=Please choose an option: 
		if "%answer%"=="1" goto :firewall
		if "%answer%"=="2" goto :policies
        if "%answer%"=="3" goto :services
        if "%answer%"=="4" goto :remconnect
        if "%answer%"=="5" goto :cgroup
        if "%answer%"=="6" goto :umanager

		if "%answer%"=="-1" exit
		if "%answer%"=="69" shutdown /r
	pause


:firewall
    echo Enabling Windows Firewall...

    :: Enable Windows Firewall for all profiles (Domain, Private, and Public)
    netsh advfirewall set allprofiles state on

    echo Windows Firewall has been enabled for all profiles.

    pause
    goto :menu

:policies
    :: Set Enforce Password History to 24
    net accounts /uniquepw:24

    :: Set Maximum Password Age to 60 days
    net accounts /maxpwage:60

    :: Set Minimum Password Age to 1 day
    net accounts /minpwage:1

    :: Set Minimum Password Length to 10 characters
    net accounts /minpwlen:10

    :: Enable Password Complexity Requirements
    secedit /export /cfg %temp%\secpol.cfg
    (for /f "tokens=*" %%i in ('findstr /v "PasswordComplexity" %temp%\secpol.cfg') do @echo %%i) > %temp%\newsecpol.cfg
    echo "PasswordComplexity = 1" >> %temp%\newsecpol.cfg
    secedit /configure /db %temp%\secedit.sdb /cfg %temp%\newsecpol.cfg

    :: Disable Store Password using Reversible Encryption
    (for /f "tokens=*" %%i in ('findstr /v "ClearTextPassword" %temp%\newsecpol.cfg') do @echo %%i) > %temp%\finalsecpol.cfg
    echo "ClearTextPassword = 0" >> %temp%\finalsecpol.cfg
    secedit /configure /db %temp%\secedit.sdb /cfg %temp%\finalsecpol.cfg

    :: Clean up temporary files
    del %temp%\secpol.cfg
    del %temp%\newsecpol.cfg
    del %temp%\finalsecpol.cfg

    echo Password policies have been configured.


    :: Set Account Lockout Threshold to 10 invalid logon attempts
    net accounts /lockoutthreshold:10

    :: Set Account Lockout Duration to 30 minutes
    net accounts /lockoutduration:30

    :: Set Reset Account Lockout Counter After to 30 minutes
    net accounts /lockoutwindow:30

    echo Account lockout policies have been configured.


    echo Forcing all users to change password at next logon...

    :: Loop through all local users and set 'Password expires' to True
    for /f "tokens=*" %%a in ('wmic useraccount where "LocalAccount='TRUE' and Disabled='FALSE'" get Name /value ^| findstr "="') do (
        set "user=%%a"
        setlocal enabledelayedexpansion
        set "username=!user:~5!"
        wmic UserAccount where Name="!username!" set PasswordExpires=True
        wmic UserAccount where Name="!username!" set PasswordChangeable=True
        net user "!username!" /logonpasswordchg:yes
        endlocal
    )

    echo All users must change their password at next logon.


    echo Enabling restriction of blank passwords for local accounts...

    :: Enable the policy to limit blank passwords to console logon only
    secedit /set /cfg "C:\Windows\security\local.sdb" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f

    :: Verify that the policy was set
    secedit /export /cfg %temp%\secpol.cfg
    findstr /C:"LimitBlankPasswordUse" %temp%\secpol.cfg

    echo Blank password usage has been limited to console logon only.

    echo Enabling the policy to prevent account enumeration...

    :: Enable the policy to prevent enumeration of the same accounts
    secedit /set /cfg "C:\Windows\security\local.sdb" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f

    :: Verify that the policy was set
    secedit /export /cfg %temp%\secpol.cfg
    findstr /C:"LimitBlankPasswordUse" %temp%\secpol.cfg

    echo Account enumeration policy has been enabled.

    pause
    goto :menu


:services
    echo Stopping and disabling services...

    :: Define the services to be stopped and disabled
    set services=TapiSrv TlntSvr ftpsvc SNMP SessionEnv TermService UmRdpService SharedAccess remoteRegistry SSDPSRV W3SVC SNMPTRAP remoteAccess RpcSs HomeGroupProvider HomeGroupListener

    :: Loop through each service and perform stop and disable actions
    for %%s in (%services%) do (
        echo Stopping %%s...
        sc stop %%s
        echo Disabling %%s...
        sc config %%s start= disabled
    )

    echo All specified services have been stopped and disabled.


    echo Stopping and disabling Microsoft FTP Service...

    :: Stop the FTP service
    net stop "Microsoft FTP Service"

    :: Disable the FTP service
    sc config "Microsoft FTP Service" start= disabled

    echo Microsoft FTP Service has been stopped and disabled.

    pause
    goto :menu


:remconnect
    echo Disabling remote connections...

    :: Disable Remote Desktop
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_SZ /d "0" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f

    :: Optionally, disable Remote Assistance
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f

    echo Remote connections have been disabled.

    pause
    goto :menu

:cgroup
    :: Prompt the user for the group name
    set /p groupName="Enter the name of the group to create: "

    :: Create the new group
    net localgroup "%groupName%" /add
    echo Group "%groupName%" has been created.

    :: Loop for user input
    :inputUsers
    set /p userName="Enter the username to add to the group (or type 'done' to finish): "

    :: Check if the user is done adding users
    if /i "%userName%"=="done" goto end

    :: Add the user to the group
    net localgroup "%groupName%" "%userName%" /add
    echo User "%userName%" has been added to group "%groupName%".

    :: Repeat the input prompt
    goto inputUsers

    :end
    echo All users have been added to the group "%groupName%".

    pause
    goto :menu


:umanager
    :: Prompt the user for the location of the text file
    set /p filePath="Enter the full path of the text file containing authorized users: "

    :: Get the username of the user running the script
    set "currentUser=%USERNAME%"
    echo Current user: !currentUser!

    :: Define a secure password
    set "securePassword=SecureP@ssword123!"

    :: Check if the file exists
    if exist "%filePath%" (
        echo Opening "%filePath%"...
        echo.

        :: Variables to track titles
        set "foundAdmins=0"
        set "foundUsers=0"
        set "rolesFound=0"
        set "adminIndex=0"
        set "userIndex=0"

        :: Read the file line by line
        for /f "usebackq delims=" %%a in ("%filePath%") do (
            set "line=%%a"

            :: Check for titles
            if "!line!"=="Authorized Administrators" (
                set "foundAdmins=1"
                set "foundUsers=0"  
                set "rolesFound=0" 
                echo Title found: !line!
                echo.
                continue
            )

            if "!line!"=="Authorized Users" (
                set "foundUsers=1"
                set "foundAdmins=0"  
                set "rolesFound=0" 
                echo Title found: !line!
                echo.
                continue
            )

            if "!line!"=="Roles" (
                set "rolesFound=1"
                set "foundAdmins=0"  
                set "foundUsers=0" 
                echo Title found: !line!
                echo.
                continue
            )

            :: Set usernames based on the title found
            if !foundAdmins! equ 1 (
                set /a adminIndex+=1
                set "adminUsername[!adminIndex!]=!line!"
                echo Authorized Administrator !adminIndex!: !line!
            )

            if !foundUsers! equ 1 (
                set /a userIndex+=1
                set "userUsername[!userIndex!]=!line!"
                echo Authorized User !userIndex!: !line!
            )

            :: Check for roles if in roles section
            if !rolesFound! equ 1 (
                for /f "tokens=1,2 delims=:" %%b in ("!line!") do (
                    set "username=%%b"
                    set "role=%%c"

                    :: Check if the user is an admin but doesn't have the admin role
                    for /l %%i in (1,1,!adminIndex!) do (
                        if "!adminUsername[%%i]!"=="!username!" (
                            if "!role!"==" user" (
                                echo Granting admin permissions to !username!...
                                net localgroup Administrators !username! /add
                            )
                        )
                    )

                    :: Check if the user is a normal user but has admin rights
                    for /l %%j in (1,1,!userIndex!) do (
                        if "!userUsername[%%j]!"=="!username!" (
                            if "!role!"==" admin" (
                                echo Revoking admin permissions from !username!...
                                net localgroup Administrators !username! /delete
                            )
                        )
                    )
                )
            )
        )

        echo.
        echo All Authorized Administrators stored in variables:
        for /l %%i in (1,1,!adminIndex!) do (
            echo Authorized Administrator %%i: !adminUsername[%%i]!
        )

        echo.
        echo All Authorized Users stored in variables:
        for /l %%i in (1,1,!userIndex!) do (
            echo Authorized User %%i: !userUsername[%%i]!
        )

        echo.
        echo Checking for users on the machine that are not in the authorized lists...

        :: List all users on the machine
        for /f "tokens=1" %%u in ('net user') do (
            set "currentUser=%%u"
            set "isAuthorized=0"

            :: Check if the current user is in the authorized lists
            for /l %%i in (1,1,!adminIndex!) do (
                if "!adminUsername[%%i]!"=="!currentUser!" (
                    set "isAuthorized=1"
                )
            )

            for /l %%j in (1,1,!userIndex!) do (
                if "!userUsername[%%j]!"=="!currentUser!" (
                    set "isAuthorized=1"
                )
            )

            :: If the user is not authorized, delete them
            if !isAuthorized! equ 0 (
                echo Deleting unauthorized user: !currentUser!...
                net user "!currentUser!" /delete
            ) else (
                :: If the user is authorized, change their password
                if "!currentUser!" NEQ "%USERNAME%" (
                    echo Changing password for user: !currentUser!...
                    net user "!currentUser!" "!securePassword!"
                )
            )
        )
    ) else (
        echo File not found: "%filePath%"
    )


    pause
    goto :menu