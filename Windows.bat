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

    :: Configure password policies
    echo Enforcing password history to remember the last 5 passwords...
    net accounts /uniquepw:24

    echo Setting maximum password age to 60 days...
    net accounts /maxpwage:60

    echo Setting minimum password age to 1 day...
    net accounts /minpwage:1

    echo Setting minimum password length to 8 characters...
    net accounts /minpwlen:10

    :: Enable password complexity requirements
    echo Enabling password complexity requirements...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "PasswordComplexity" /t REG_DWORD /d 1 /f

    :: Disable storing passwords using reversible encryption
    echo Disabling store passwords using reversible encryption...
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "ClearTextPassword" /t REG_DWORD /d 0 /f

    :: Force update group policies
    echo Updating group policies...
    gpupdate /force

    echo Password policies have been configured.

    pause
    goto :menu


:services

    :: Disable Microsoft FTP Service
    echo Stopping Microsoft FTP Service...
    net stop ftpsvc >nul 2>&1

    echo Disabling Microsoft FTP Service startup...
    sc config ftpsvc start= disabled >nul 2>&1

    echo Microsoft FTP Service has been disabled.

    pause
    goto :menu


:remconnect
    echo Disabling remote connections...

    :: Disable Remote Desktop
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_SZ /d "0" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f

    :: Optionally, disable Remote Assistance
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f


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
    set "securePassword=LittleBobby@123!"

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