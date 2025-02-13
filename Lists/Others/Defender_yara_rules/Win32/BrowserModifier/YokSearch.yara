rule BrowserModifier_Win32_YokSearch_17663_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/YokSearch"
        threat_id = "17663"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "YokSearch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yok.dll" ascii //weight: 1
        $x_1_2 = "yok.exe" ascii //weight: 1
        $x_1_3 = "YOK.ico" ascii //weight: 1
        $x_1_4 = "YOKUPDWClass" ascii //weight: 1
        $x_1_5 = "www.yok.com/go" ascii //weight: 1
        $x_1_6 = "Software\\YOK\\Coop" ascii //weight: 1
        $x_1_7 = "SoftWare\\Yok\\Toolbar" ascii //weight: 1
        $x_1_8 = "\\yoksch.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule BrowserModifier_Win32_YokSearch_17663_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/YokSearch"
        threat_id = "17663"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "YokSearch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 00 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 59 4b 45 45 50 45 52 00 00 44 65 76 69 63 65 4e 61 6d 65 00}  //weight: 4, accuracy: High
        $x_4_2 = "TYKeeper.vxd" ascii //weight: 4
        $x_3_3 = "autolive.dll" ascii //weight: 3
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_5 = "RegCreateKeyExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_YokSearch_17663_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/YokSearch"
        threat_id = "17663"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "YokSearch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "block.yok.com" ascii //weight: 1
        $x_1_2 = "SoftWare\\Microsoft\\Internet Explorer\\Yokbar" ascii //weight: 1
        $x_1_3 = "www.yok.com/go" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\MenuExt\\YOK" ascii //weight: 1
        $x_1_5 = "yokymt.exe" ascii //weight: 1
        $x_1_6 = "yokymtdata.ymt" ascii //weight: 1
        $x_1_7 = "yokupdate.dat" ascii //weight: 1
        $x_1_8 = "yoklog.txt" ascii //weight: 1
        $x_1_9 = "yokdow.exe" ascii //weight: 1
        $x_1_10 = "yoksch.htm" ascii //weight: 1
        $x_1_11 = "yokdat.exe" ascii //weight: 1
        $x_1_12 = "yokpro.exe" ascii //weight: 1
        $x_1_13 = "yokupd.exe" ascii //weight: 1
        $x_1_14 = "yokbar.inf" ascii //weight: 1
        $x_1_15 = "yokcol.dll" ascii //weight: 1
        $x_1_16 = "yokbar.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

