rule Trojan_Win64_GoGetter_Gen_2147814405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGetter.Gen!dha"
        threat_id = "2147814405"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGetter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "200"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0f 1f 40 00 48 39 cb 75 11 48 89 c3 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 9e}  //weight: 100, accuracy: Low
        $x_100_2 = {c6 44 24 1f 03 48 8b 94 24 ?? 01 00 00 48 8b ?? ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoGetter_B_2147816340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGetter.B!dha"
        threat_id = "2147816340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGetter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 1f 40 00 48 39 cb 75 11 48 89 c3 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 9e}  //weight: 10, accuracy: Low
        $x_10_2 = {03 75 0d 66 81 38 65 6e 75 06 80 78 02 64 74}  //weight: 10, accuracy: High
        $x_90_3 = {c6 44 24 1f 03 48 8b 94 24 ?? 01 00 00 48 8b ?? ff}  //weight: 90, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_90_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_GoGetter_C_2147816341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGetter.C!dha"
        threat_id = "2147816341"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGetter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 1f 40 00 48 39 cb 75 11 48 89 c3 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 9e}  //weight: 10, accuracy: Low
        $x_10_2 = {03 75 0d 66 81 38 65 6e 75 06 80 78 02 64 74}  //weight: 10, accuracy: High
        $x_90_3 = {c6 44 24 3f 03 48 8b 84 24 ?? 00 00 00 48 ?? ?? ?? e8}  //weight: 90, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_90_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_GoGetter_D_2147816342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGetter.D!dha"
        threat_id = "2147816342"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGetter"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "proxy/pkg/client.(*Client).connectToRemote" ascii //weight: 10
        $x_10_2 = "proxy/pkg/client.(*Client).handleSession" ascii //weight: 10
        $x_10_3 = "proxy/pkg/client.(*Client).connectToTarget" ascii //weight: 10
        $x_10_4 = "proxy/pkg/client.handleConnection" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

