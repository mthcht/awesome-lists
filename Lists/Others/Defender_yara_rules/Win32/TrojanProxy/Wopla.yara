rule TrojanProxy_Win32_Wopla_AG_2147596690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wopla.AG"
        threat_id = "2147596690"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\device\\poofpoof" wide //weight: 1
        $x_1_2 = "\\driver\\kprof" wide //weight: 1
        $x_1_3 = "ZwQueryInformationFile" ascii //weight: 1
        $x_1_4 = "zwquerysysteminformation" ascii //weight: 1
        $x_1_5 = {8d 7d c0 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 33 f6 3b c6 89 45 08 7d 17 3d 01 00 00 c0 74 07 3d 25 02 00 c0 75 09 83 c7 04 8b 07 3b c6 75 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wopla_Z_2147598332_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wopla.Z"
        threat_id = "2147598332"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\YLoad\\vars" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "lamodano.info/aff-light" ascii //weight: 1
        $x_1_5 = "GetSystemWindowsDirectoryA" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Wopla_A_2147602118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wopla.gen!A"
        threat_id = "2147602118"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 83 f9 40 75 22 66 c7 84 45 ?? ?? ff ff 25 00 40 66 c7 84 45 ?? ?? ff ff 34 00 40 66 c7 84 45 ?? ?? ff ff 30 00 eb 25 66 83 f9 20 75 17 66 c7 84 45 ?? ?? ff ff 25 00 40 66 c7 84 45 ?? ?? ff ff 32 00 eb d6 66 89 8c 45 ?? ?? ff ff 40 42 0f b7 0c 57 66 3b ce}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 4c 3e 01 8d 54 3e ff eb 15 3c 7e 7d 2e 3c 2c 74 2a 3c 3b 74 26 3a c3 74 22 3c 40 74 1e 4a 8a 02 3a c3 7f e5 eb 15 3c 7e 7d 17 3c 2c 74 13 3c 3b 74 0f 3a c3 74 0b 3c 40 74 07 41 8a 01 3a c3 7f e5 42 2b ca 8d 41 fa 83 f8 79}  //weight: 10, accuracy: High
        $x_2_3 = "%04hu.%02hu.%02hu_%02hu:%02hu:%02hu_%04X_%04X.dat" ascii //weight: 2
        $x_2_4 = "mdn_log_%pidtid.txt" ascii //weight: 2
        $x_2_5 = "Subject: %08X_%08X" ascii //weight: 2
        $x_2_6 = "Software\\RIT\\The Bat!" ascii //weight: 2
        $x_2_7 = "*\\=password=\\" ascii //weight: 2
        $x_2_8 = "Microsoft_WinInet_*" ascii //weight: 2
        $x_2_9 = "mail.identity.%s.smtpServer" ascii //weight: 2
        $x_2_10 = "mail.account.account%i.identities" ascii //weight: 2
        $x_2_11 = "\\\\.\\Scsi%u:" ascii //weight: 2
        $x_2_12 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 10 of ($x_2_*))) or
            ((2 of ($x_10_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Wopla_B_2147602459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wopla.gen!B"
        threat_id = "2147602459"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 0d 50 c7 00 a5 a5 a5 a5 ff 15 ?? ?? ?? ?? 56 ff d3 e8 ?? ?? 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {75 04 6a fd eb 19 38 5d 10 74 64 80 bd ?? ?? ff ff 4d 75 09 80 bd ?? ?? ff ff 5a 74 52 6a fc 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {99 b9 d0 07 00 00 f7 f9 04 61 88 04 3e 46 3b f3 7c e8 c6 04 1f 00 8b c7}  //weight: 1, accuracy: High
        $x_1_4 = {eb 64 38 5d 10 74 3f 80 bd ?? ?? ff ff 4d 75 09 80 bd ?? ?? ff ff 5a 74 2d 6a fc eb be 53 8d 45 f0 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanProxy_Win32_Wopla_C_2147616299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wopla.gen!C"
        threat_id = "2147616299"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "71"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%sxtempx." ascii //weight: 10
        $x_10_2 = "MAIL FROM:<%s>" ascii //weight: 10
        $x_10_3 = "\\work_svn\\madonna" ascii //weight: 10
        $x_10_4 = "\\packed_Installer" ascii //weight: 10
        $x_10_5 = "gl.nulladdress.com" ascii //weight: 10
        $x_10_6 = "cmd.exe /c \"make_dll.bat" ascii //weight: 10
        $x_10_7 = "%s:*:Enabled:Windows Update" ascii //weight: 10
        $x_10_8 = "%systemroot%\\system32\\rsvpsp.dll" ascii //weight: 10
        $x_1_9 = "AF133D4E-4B35-4bd8-9A30-CE6A480E53D5" ascii //weight: 1
        $x_1_10 = "7DA51AA8-A5F2-46cc-B892-A3DF1EA4762F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            ((8 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Wopla_D_2147620946_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Wopla.gen!D"
        threat_id = "2147620946"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wopla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wow64" ascii //weight: 10
        $x_10_2 = "\\\\.\\Scsi%u:" ascii //weight: 10
        $x_10_3 = "SeDebugPrivilege" ascii //weight: 10
        $x_1_4 = "89.149.226.52" ascii //weight: 1
        $x_1_5 = "AF133D4E-4B35-4bd8-9A30-CE6A480E53D5" ascii //weight: 1
        $x_1_6 = "7DA51AA8-A5F2-46cc-B892-A3DF1EA4762F" ascii //weight: 1
        $x_1_7 = "CFE7F539-7305-48f8-9E76-2EB71ECA67D1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

