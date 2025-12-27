rule Trojan_Win32_Lazarus_AR_2147756373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazarus.AR!MTB"
        threat_id = "2147756373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazarus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://stokeinvestor.com/common.php" ascii //weight: 10
        $x_10_2 = "https://growthincone.com/board.php" ascii //weight: 10
        $x_10_3 = "https://inverstingpurpose.com/head.php" ascii //weight: 10
        $x_1_4 = "cmd.exe /c" ascii //weight: 1
        $x_1_5 = "urlmon.dll" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lazarus_A_2147954098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lazarus.A"
        threat_id = "2147954098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lazarus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetLogicalDriveStringsW-GetDriveType.exe" ascii //weight: 1
        $x_1_2 = "%TMP%" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-bh2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

