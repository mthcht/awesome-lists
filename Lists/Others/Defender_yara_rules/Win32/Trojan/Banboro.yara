rule Trojan_Win32_Banboro_A_2147697188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Banboro.A"
        threat_id = "2147697188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Banboro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 52 42 20 42 61 6e 6b 6e 65 74 20 96 20 42 61 6e 63 6f 20 64 65 20 42 72 61 73 ed 6c 69 61}  //weight: 1, accuracy: High
        $x_1_2 = "4D6F7A696C6C612046697265666F78" ascii //weight: 1
        $x_1_3 = "Gerenciador de Tarefas do Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

