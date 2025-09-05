rule Trojan_Linux_MsfwBindShell_NA_2147951554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwBindShell.NA!!MsfwBindShell.gen!NA"
        threat_id = "2147951554"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwBindShell"
        severity = "Critical"
        info = "MsfwBindShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NA: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 50 6a 29 58 99 6a 02 5f 6a 01 5e 0f 05 48 85 c0 78 [0-14] 51 48 89 e6 54 5e 6a 31 58 6a 10 5a 0f 05 6a 32 58 6a 01 5e 0f 05 6a 2b 58 99 52 52 54 5e 6a 1c 48 8d 14 24 0f 05}  //weight: 1, accuracy: Low
        $x_1_2 = {5e 48 31 c0 48 ff c0 0f 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_MsfwBindShell_NB_2147951555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MsfwBindShell.NB!!MsfwBindShell.gen!NB"
        threat_id = "2147951555"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MsfwBindShell"
        severity = "Critical"
        info = "MsfwBindShell: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "NB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 29 58 99 6a 01 5e 6a 02 5f 0f 05 97 b0 32 0f 05 96 b0 2b 0f 05 [0-2] ff ce 6a 21 58 0f 05 75 f7 52 48 bf 2f 2f 62 69 6e 2f 73 68 57 54 5f b0 3b 0f 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

