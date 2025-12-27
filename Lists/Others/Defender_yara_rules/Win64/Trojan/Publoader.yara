rule Trojan_Win64_Publoader_A_2147957209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Publoader.A!dha"
        threat_id = "2147957209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Publoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Error: File Corrupted" ascii //weight: 1
        $x_1_2 = "The PDF file is corrupted. Please restart your computer to try again." ascii //weight: 1
        $x_1_3 = "helper_process.exe NVIDIAGeForce" ascii //weight: 1
        $x_1_4 = "Mery altion failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

