rule Trojan_Win32_RansNoteDrop_BP_2147773508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RansNoteDrop.BP"
        threat_id = "2147773508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RansNoteDrop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "corpleaks.net" ascii //weight: 1
        $x_1_2 = "hxt254aygrsziejn.onion" ascii //weight: 1
        $x_1_3 = "tutanota.com" ascii //weight: 1
        $x_1_4 = "protonmail.com " ascii //weight: 1
        $x_1_5 = "crypt32.dll" ascii //weight: 1
        $x_1_6 = "GetDriveTypeW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

