rule Backdoor_Win32_Dowshagen_A_2147647392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dowshagen.A"
        threat_id = "2147647392"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dowshagen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--Spread Via LimeWire--" wide //weight: 1
        $x_1_2 = "--Disable Windows Update--" wide //weight: 1
        $x_1_3 = "--Infect All--" wide //weight: 1
        $x_1_4 = "--AV Kill [UD]--" wide //weight: 1
        $x_10_5 = "Shadow Batch Virus Generator" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

