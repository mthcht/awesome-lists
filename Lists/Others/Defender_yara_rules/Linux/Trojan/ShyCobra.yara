rule Trojan_Linux_ShyCobra_C_2147961417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShyCobra.C!dha"
        threat_id = "2147961417"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShyCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 0e 5a be ?? 3c 03 01 e8 ?? ?? fd ff 66 85 c0 0f}  //weight: 10, accuracy: Low
        $x_10_2 = "[PERFORM_RELOC] Done: processed=[6x-DBG]" ascii //weight: 10
        $x_10_3 = "[MEMLOAD-DBG] Proc load FAILED" ascii //weight: 10
        $x_10_4 = "PORTFWD: local=error:" ascii //weight: 10
        $x_10_5 = "hijack failed: ,\"mode\":\"thread_hijack" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_ShyCobra_B_2147961419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShyCobra.B!dha"
        threat_id = "2147961419"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShyCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "8.149.128.10" ascii //weight: 20
        $x_10_2 = {6a 0b 58 be 00 00 00 01 48 8b 7d c0 0f 05}  //weight: 10, accuracy: High
        $x_10_3 = {48 c7 06 fc 1c 00 01 48 c7 46 08}  //weight: 10, accuracy: High
        $x_10_4 = {48 c7 46 10 ec 1e 00 01 48 83 66 18 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_ShyCobra_A_2147961429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShyCobra.A!dha"
        threat_id = "2147961429"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShyCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 69 c8 40 42 0f 00 31 db be e8 03 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {31 d2 f7 f6 41 89 c6 be 00 ca 9a 3b}  //weight: 10, accuracy: High
        $x_10_3 = "/dev/shm/.x" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_ShyCobra_D_2147968249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShyCobra.D!dha"
        threat_id = "2147968249"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShyCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 47 fb 17 03 03 00 c6 47 ff 35 48 8d 95}  //weight: 10, accuracy: High
        $x_10_2 = "[BEACON] Encrypted, len=[BEACON] Sending encrypted payload" ascii //weight: 10
        $x_10_3 = "[DECRYPT] Decryption successful, len=[BEACON] Plaintext mode" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_ShyCobra_E_2147968250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ShyCobra.E!dha"
        threat_id = "2147968250"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ShyCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 b9 72 2f 75 31 36 3a 31 5d 48 89 48 07 48 b9 5b 6b 77 6f 72 6b 65 72}  //weight: 10, accuracy: High
        $x_10_2 = "VoidLink Implant Core" ascii //weight: 10
        $x_10_3 = "172.20.0.10" ascii //weight: 10
        $x_10_4 = "beacon_stealth_exec" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

