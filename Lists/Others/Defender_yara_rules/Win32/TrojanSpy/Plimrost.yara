rule TrojanSpy_Win32_Plimrost_B_2147690960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Plimrost.B"
        threat_id = "2147690960"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Plimrost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HardCore Software For : Public" wide //weight: 1
        $x_1_2 = "?action=add&username=" wide //weight: 1
        $x_1_3 = {f4 02 a9 e7 0b ?? ?? ?? ?? 23 ?? ?? 2a 31 ?? ?? 32 04 00 ?? ?? ?? ?? 35 ?? ?? 04 ?? ?? 64 72 ff 10 00}  //weight: 1, accuracy: Low
        $x_1_4 = {f4 3e eb 6e ?? ?? b3 fb e6 e5 70 ?? ?? 35 ?? ?? 6b ?? ?? f4 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Plimrost_D_2147718086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Plimrost.D!bit"
        threat_id = "2147718086"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Plimrost"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Module>{276D2394-0155-4C14-BACF-1189245073D9}" ascii //weight: 1
        $x_1_2 = "<PrivateImplementationDetails>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

