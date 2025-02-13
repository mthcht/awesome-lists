rule Backdoor_Win32_Dsklite_G_2147597944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dsklite.G"
        threat_id = "2147597944"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dsklite"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "113"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\Administrator\\My Documents\\winrar\\server\\Project1.vbp" wide //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Active Setup\\Installed Components\\{44BBA855-CC51-11CF-BAFA-00BB00B6017B}" wide //weight: 1
        $x_1_5 = "HKEY_CURRENT_USER\\Software\\America Online\\AOL Instant Messenger (TM)\\CurrentVersion\\Login\\Screen Name" wide //weight: 1
        $x_1_6 = "HKEY_CURRENT_USER\\Software\\Kazaa\\UserDetails\\Email" wide //weight: 1
        $x_1_7 = "Soldiers Of Anarchy CD Key:" wide //weight: 1
        $x_1_8 = "Need For Speed: Hot Pursuit 2 CD Key:" wide //weight: 1
        $x_1_9 = "hello Iam Back Diable Rat Hacker Your System Good Bey Beby" wide //weight: 1
        $x_1_10 = "Hi My Dog . How Are You" wide //weight: 1
        $x_1_11 = "openemail" wide //weight: 1
        $x_1_12 = "mailto:" wide //weight: 1
        $x_1_13 = "Passwords;" wide //weight: 1
        $x_1_14 = "C:\\WINDOWS\\diable.CMD" wide //weight: 1
        $x_1_15 = "\\Kernel.bat" wide //weight: 1
        $x_1_16 = "ksin.SProject1" ascii //weight: 1
        $x_1_17 = "Diable Rat V2.0 Online Victem" ascii //weight: 1
        $x_100_18 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 13 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Dsklite_H_2147609657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dsklite.H"
        threat_id = "2147609657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dsklite"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Active Setup\\Installed Components\\{44BBA855-CC51-11CF-BAFA-00BB00B6017B}\\StubPath" wide //weight: 10
        $x_10_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\KAZAA\\LocalContent\\DownloadDir" wide //weight: 10
        $x_10_3 = "\\Kernel.bat" wide //weight: 10
        $x_10_4 = "C:\\WINDOWS\\Start Menu\\Programs\\StartUp\\Kaspersky Anti-Hacker.lnk" wide //weight: 10
        $x_10_5 = "Del bat.bat" wide //weight: 10
        $x_5_6 = {41 00 2f 00 76 00 20 00 26 00 20 00 46 00 [0-16] 6c 00 6c 00 20 00 4b 00 69 00 6c 00 6c 00 69 00 6e 00 67 00 3a 00}  //weight: 5, accuracy: Low
        $x_1_7 = "http://wwp.icq.com/scripts/WWPMsg.dll?from=" wide //weight: 1
        $x_1_8 = "Fake Error Body:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

