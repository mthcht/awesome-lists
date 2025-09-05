rule Trojan_Linux_MsfwRevShell_NA_2147937930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.NA!!MsfwRevShell.gen!NA"
        threat_id = "2147937930"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 ff 6a 09 58 99 b6 10 48 89 d6 4d 31 c9 6a 22 41 5a 6a 07 5a 0f 05 48 85 c0 78 51 6a 0a 41 59 50 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 85 c0 78 3b 48 97 48 b9 02 00}  //weight: 2, accuracy: High
        $x_2_2 = {51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 25 49 ff c9 74 18 57 6a 23 58 6a 00 6a 05 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 c7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfwRevShell_NB_2147937931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.NB!!MsfwRevShell.gen!NB"
        threat_id = "2147937931"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 31 09 6a 99 58 10 b6 89 48 4d d6 c9 31 22 6a 5a 41 07 6a 0f 5a 48 05 c0 85 51 78 0a 6a 59 41 6a 50 58 29 6a 99 5f 02 01 6a 0f 5e 48 05 c0 85 3b 78 97 48 b9 48 00 02}  //weight: 2, accuracy: High
        $x_2_2 = {48 51 e6 89 10 6a 6a 5a 58 2a 05 0f 48 59 c0 85 25 79 ff 49 74 c9 57 18 23 6a 6a 58 6a 00 48 05 e7 89 31 48 0f f6 59 05 5f 59 85 48 79 c0 6a c7 58 3c 01 6a 0f 5f 5e 05 7e 6a 0f 5a 48 05 c0 85 ed 78 e6 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfwRevShell_NC_2147937932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.NC!!MsfwRevShell.gen!NC"
        threat_id = "2147937932"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NC: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 97 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 51 48 89 e6 6a 10 5a 6a 2a 58 0f 05 59 48 85 c0 79 ?? 49 ff c9 74 ?? 57 6a 23 58 6a ?? 6a ?? 48 89 e7 48 31 f6 0f 05 59 59 5f 48 85 c0 79 ?? 6a 3c 58 6a 01 5f 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfwRevShell_ND_2147947881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.ND!!MsfwRevShell.gen!ND"
        threat_id = "2147947881"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "ND: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 bb 2f 62 69 6e 2f 73 68 00 53 48 89 e7 52 57 48 89 e6 0f 05}  //weight: 1, accuracy: High
        $x_1_2 = {6a 3c 58 6a 01 5f 0f 05 5e 6a 26 5a 0f 05 48 85 c0 78 ed ff e6}  //weight: 1, accuracy: High
        $x_1_3 = {0f 05 48 96 6a 2b 58 0f 05 50 56 5f 6a 09 58 99 b6 10 48 89 d6 4d 31 c9 6a 22 41 5a b2 07 0f 05 48 96 48 97 5f 0f 05 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_MsfwRevShell_NE_2147947882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.NE!!MsfwRevShell.gen!NE"
        threat_id = "2147947882"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NE: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 53 89 e7 6a 10 54 57 53 89 e1 b3 07 ff 01 6a 66 58 cd 80 66 81 7f 02 ?? ?? 75 f1 5b 6a 02 59 b0 3f cd 80 49 79 f9 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1}  //weight: 1, accuracy: Low
        $x_1_2 = {48 31 ff 48 31 db b3 18 48 29 dc 48 8d 14 24 48 c7 02 10 00 00 00 48 8d 74 24 08 6a 34 58 0f 05 48 ff c7 66 81 7e 02 ?? ?? 75 f0 48 ff cf 6a 02 5e 6a 21 58 0f 05 48 ff ce 79 f6 48 89 f3 bb 41 2f 73 68 b8 2f 62 69 6e 48 c1 eb 08 48 c1 e3 20 48 09 d8 50 48 89 e7 48 31 f6 48 89 f2 6a 3b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_MsfwRevShell_NF_2147947883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.NF!!MsfwRevShell.gen!NF"
        threat_id = "2147947883"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NF: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 5e 6a 21 58 ff ce 0f 05 e0 ?? 6a 3b 58 99 48 bb 2f 62 69 6e 2f 73 68 00 53 54 5f 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfwRevShell_NG_2147951553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwRevShell.NG!!MsfwRevShell.gen!NG"
        threat_id = "2147951553"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwRevShell"
        severity = "Critical"
        info = "MsfwRevShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NG: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 2f 62 69 6e 2f 73 68 00 99 50 54 5f}  //weight: 1, accuracy: High
        $x_1_2 = {5e 6a 3b 58 0f 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

