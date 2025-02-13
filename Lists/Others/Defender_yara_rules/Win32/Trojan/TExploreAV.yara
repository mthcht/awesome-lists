rule Trojan_Win32_TExploreAV_2147723147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TExploreAV"
        threat_id = "2147723147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TExploreAV"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 45 78 70 6c 6f 72 65 20 41 56 20 53 45 54 55 50 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 78 74 72 6f 79 61 6e 2e 45 58 5f 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 4e 44 49 43 45 2e 44 4f 5f 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 52 4c 2e 55 52 5f 00 fd 9f 80 00 4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TExploreAV_2147723147_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TExploreAV"
        threat_id = "2147723147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TExploreAV"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.troyanexplore.com.ar" wide //weight: 1
        $x_1_2 = "TMR (Tratamiento Malware Residente)" wide //weight: 1
        $x_1_3 = "full / Clean-up on full version" wide //weight: 1
        $x_1_4 = ">Dudosos/Suspects" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TExploreAV_2147723147_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TExploreAV"
        threat_id = "2147723147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TExploreAV"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Troyanexplore.com.ar.URL" wide //weight: 1
        $x_1_2 = "Real-Time Protection\\DisableOnAccessProtection" wide //weight: 1
        $x_1_3 = "TroyanExplore\\Instalar.vbp" wide //weight: 1
        $x_1_4 = "Instalador TExplore Antivirus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

