rule Trojan_Win64_LegacyHive_DA_2147973393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LegacyHive.DA!MTB"
        threat_id = "2147973393"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LegacyHive"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" ascii //weight: 1
        $x_1_2 = "Local AppData" ascii //weight: 1
        $x_1_3 = "\\\\.\\globalroot\\BaseNamedObjects\\Restricted" ascii //weight: 1
        $x_1_4 = "\\BaseNamedObjects\\Restricted\\Microsoft" ascii //weight: 1
        $x_1_5 = "UsrClass.dat" ascii //weight: 1
        $x_1_6 = "ntuser.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

