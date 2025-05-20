rule Trojan_Win32_ScreenConnect_EA_2147941743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ScreenConnect.EA!MTB"
        threat_id = "2147941743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ScreenConnect"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e=Support&y=Guest" wide //weight: 2
        $x_2_2 = "h=relay.pcx140.ru" wide //weight: 2
        $x_2_3 = "s=0d750938-28d4-4871-8436-3ad0e88f8abb" wide //weight: 2
        $x_2_4 = "k=BgIAAACkAABSU0ExAAgAAAEAAQDF" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

