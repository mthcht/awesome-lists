rule Trojan_MSIL_ShelahoLoader_A_2147778830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShelahoLoader.A!dha"
        threat_id = "2147778830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShelahoLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Starting shell process" wide //weight: 1
        $x_1_2 = "[x] Failed to read process memory!" wide //weight: 1
        $x_1_3 = "[x] Shellcode buffer is too long!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

