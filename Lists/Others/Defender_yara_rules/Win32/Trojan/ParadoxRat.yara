rule Trojan_Win32_ParadoxRat_RB_2147844187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ParadoxRat.RB!MTB"
        threat_id = "2147844187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ParadoxRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w1DVa8xnH3oDk4RCOqtuazZWDDQHdDU4F2LTtceHhK2lZeM1nLZLno70xR7WRxxMjYcgXD58YDYIRE0jNwcf5KAnbDYEDUfM" ascii //weight: 1
        $x_1_2 = "6a16HEI4rmNEYLkVWPWP3VZU4oh5j" ascii //weight: 1
        $x_1_3 = "RootkitRemover.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

