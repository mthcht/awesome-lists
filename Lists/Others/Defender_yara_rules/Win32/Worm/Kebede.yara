rule Worm_Win32_Kebede_A_2147581555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kebede.gen!A"
        threat_id = "2147581555"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kebede"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "4D5A90000300000004000000FFFF0000B8" wide //weight: 5
        $x_5_2 = "8F8AF9DBCBEB9788CBEB9788CBEB978848F79988CAEB9788A2F4" wide //weight: 5
        $x_2_3 = "127.0.0.1" wide //weight: 2
        $x_2_4 = "lstWabFile" ascii //weight: 2
        $x_2_5 = "lstmail" ascii //weight: 2
        $x_2_6 = "lstmailer" ascii //weight: 2
        $x_2_7 = "Kebede" wide //weight: 2
        $x_2_8 = "KebedeE" ascii //weight: 2
        $x_3_9 = "Window Layerd Service Provider" ascii //weight: 3
        $x_2_10 = "SocketControl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 7 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Kebede_B_2147581556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kebede.gen!B"
        threat_id = "2147581556"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kebede"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Next</a>" wide //weight: 1
        $x_1_2 = "Imkwquqyg\\Rvz Wvusngu\\" wide //weight: 1
        $x_1_3 = "jggd://" wide //weight: 1
        $x_1_4 = "\\Windows\\CurrentVersion\\Internet Settings" wide //weight: 1
        $x_1_5 = "ProxyEnable" wide //weight: 1
        $x_1_6 = "Uvxwkj" wide //weight: 1
        $x_1_7 = "ugLxiv=" wide //weight: 1
        $x_1_8 = "*.rvzczp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Kebede_C_2147581557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kebede.gen!C"
        threat_id = "2147581557"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kebede"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scripting.filesystemobject" wide //weight: 1
        $x_1_2 = "wscript.shell" wide //weight: 1
        $x_1_3 = "getspecialfolder" wide //weight: 1
        $x_1_4 = "CurrentVersion\\Winlogon\\Shell" wide //weight: 1
        $x_1_5 = "Explorer\\Advanced\\HideFileExt" wide //weight: 1
        $x_1_6 = "Explorer\\Main\\Window Title" wide //weight: 1
        $x_1_7 = "drivers\\etc\\hosts" wide //weight: 1
        $x_1_8 = "www.bitdefender." wide //weight: 1
        $x_1_9 = "www.nod32." wide //weight: 1
        $x_1_10 = "www.norman." wide //weight: 1
        $x_1_11 = "wscript.network" wide //weight: 1
        $x_1_12 = ".pdf.exe" wide //weight: 1
        $x_1_13 = "net user administrator" wide //weight: 1
        $x_1_14 = ".exe\\PersistentHandler" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

rule Worm_Win32_Kebede_D_2147581558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kebede.gen!D"
        threat_id = "2147581558"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kebede"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "127.0.0.1" wide //weight: 2
        $x_2_2 = "HIJACK" wide //weight: 2
        $x_1_3 = "BIDEF" wide //weight: 1
        $x_1_4 = "i386\\taskmgr.exe" wide //weight: 1
        $x_1_5 = "i386\\regedit.exe" wide //weight: 1
        $x_1_6 = "i386\\tskill.exe" wide //weight: 1
        $x_1_7 = "i386\\taskkill.exe" wide //weight: 1
        $x_1_8 = "i386\\tasklist.exe" wide //weight: 1
        $x_1_9 = "dllcache\\taskkill.exe" wide //weight: 1
        $x_1_10 = "dllcache\\taskmgr.exe" wide //weight: 1
        $x_1_11 = "dllcache\\regedit.exe" wide //weight: 1
        $x_3_12 = "Kebede\\Dropper" wide //weight: 3
        $x_1_13 = "EnumProcessModules" ascii //weight: 1
        $x_1_14 = "CreateMutexA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

