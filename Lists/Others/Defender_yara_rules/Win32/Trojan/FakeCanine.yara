rule Trojan_Win32_FakeCanine_141628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeCanine"
        threat_id = "141628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeCanine"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 38 02 0f 85 ?? 00 00 00 68 ?? ?? 46 00 68 ?? ?? 46 00 e8 ?? ?? f9 ff 50 e8 ?? ?? f9 ff 80 38 e8 75 ?? 6a 34}  //weight: 3, accuracy: Low
        $x_1_2 = "Software\\GuardDog Computing" ascii //weight: 1
        $x_1_3 = "and get a discount of 20$." ascii //weight: 1
        $x_1_4 = "to avoid participating in criminal activity." ascii //weight: 1
        $x_1_5 = "Your computer can be infected. Do you want" ascii //weight: 1
        $x_1_6 = "seems that your computer is infected with W32:Virut virus." ascii //weight: 1
        $x_1_7 = "against identity thieves, grabbers, data miners, etc." ascii //weight: 1
        $x_1_8 = "scanning active processes every second and terminating susp" ascii //weight: 1
        $x_1_9 = "Possible Identity Theft Detected!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

