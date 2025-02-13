rule Trojan_Win64_ExpMaster_RPX_2147847278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ExpMaster.RPX!MTB"
        threat_id = "2147847278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ExpMaster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramData\\\\1.bat" ascii //weight: 1
        $x_1_2 = "Swaping shell." ascii //weight: 1
        $x_1_3 = "Author: SBSB" ascii //weight: 1
        $x_1_4 = "K32EnumDeviceDrivers" ascii //weight: 1
        $x_1_5 = "Maybe patched!" ascii //weight: 1
        $x_1_6 = "CVE-2018-8639-exp-master" ascii //weight: 1
        $x_1_7 = "exp.pdb" ascii //weight: 1
        $x_1_8 = "Trigger vul." ascii //weight: 1
        $x_1_9 = "EnumDeviceDrivers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

