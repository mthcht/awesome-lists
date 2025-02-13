rule Trojan_Win64_JaggedToe_C_2147911601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/JaggedToe.C!dha"
        threat_id = "2147911601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "JaggedToe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 ?? 25 73 0a 00 44 69 73 6b 48 61 6e 64 6c 65 3a 20 25 64 2c 20 57 69 70 65 64 3a 20 25 64 2c 20 45 72 72 6f 72 3a 20 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_JaggedToe_D_2147911602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/JaggedToe.D!dha"
        threat_id = "2147911602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "JaggedToe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lla/ teIuq/ swodahs   eteled nimdassv  c/ exe.dm" ascii //weight: 1
        $x_1_2 = "seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dm" ascii //weight: 1
        $x_1_3 = "eteled ypocwodahs cimw c/ exe.dm" ascii //weight: 1
        $x_1_4 = "on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_JaggedToe_E_2147911603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/JaggedToe.E!dha"
        threat_id = "2147911603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "JaggedToe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 2b 5d 20 53 74 61 74 73 3a 20 25 64 20 7c 20 25 64 0a}  //weight: 1, accuracy: High
        $x_1_2 = "[!] Waiting For  Queue" ascii //weight: 1
        $x_1_3 = "[!] Waiting For Queue" ascii //weight: 1
        $x_1_4 = "Deleting Disks..." ascii //weight: 1
        $x_1_5 = {44 69 73 6b 4e 61 6d 65 3a 20 25 73 2c 20 44 65 6c 65 74 65 64 3a 20 25 64 20 2d 20 25 64 0a}  //weight: 1, accuracy: High
        $x_1_6 = {5b 2b 5d 20 52 6f 75 6e 64 20 25 64 0a}  //weight: 1, accuracy: High
        $x_1_7 = {5b 2b 5d 20 43 50 55 3a 20 25 64 20 2c 20 54 68 72 65 61 64 73 3a 20 25 64 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

