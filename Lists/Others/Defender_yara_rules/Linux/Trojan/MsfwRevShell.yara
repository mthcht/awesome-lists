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

