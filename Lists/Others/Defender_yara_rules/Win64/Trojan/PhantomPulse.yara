rule Trojan_Win64_PhantomPulse_B_2147968204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhantomPulse.B"
        threat_id = "2147968204"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhantomPulse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 10 01 c2 81 e2 ff 03 00 00 c1 e8 04 03 04 91 49 83 c0 01 4d 39 c8 75 e5}  //weight: 1, accuracy: High
        $x_1_2 = {42 0f b6 14 01 44 01 c2 81 e2 ff 03 00 00 41 89 c3 45 03 1c 91 41 69 d3 ?? ?? ?? ?? c1 e8 0b 01 d0 4c 89 c2 49 83 c0 01 4c 39 d2 75 d3}  //weight: 1, accuracy: Low
        $x_1_3 = {89 c1 c1 e1 05 29 c1 41 0f b6 10 c1 e8 07 01 d0 25 ff 03 00 00 41 03 0c 81 89 c8 49 83 c0 01 4d 39 d0 75 dc}  //weight: 1, accuracy: High
        $x_1_4 = {ba 2d 39 08 d9}  //weight: 1, accuracy: High
        $x_1_5 = {ba 78 b5 b9 93}  //weight: 1, accuracy: High
        $x_1_6 = {ba 79 00 78 69}  //weight: 1, accuracy: High
        $x_1_7 = {45 8b 0c 83 41 ba a7 c6 67 4e 49 01 c9 45 8a 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win64_PhantomPulse_APP_2147970966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhantomPulse.APP!MTB"
        threat_id = "2147970966"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhantomPulse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b7 0c 43 44 8d 49 bf 44 8d 41 20 66 41 83 f9 1a 44 0f 43 c1 8d 0c c5 00 00 00 00 83 e1 18 45 89 d1 41 d3 e9 44 32 0c 02 45 38 c1 75 11 48 ff c0}  //weight: 2, accuracy: High
        $x_1_2 = "dropper exits after handoff" ascii //weight: 1
        $x_1_3 = "elevate marker found but we're the DROPPER" ascii //weight: 1
        $x_1_4 = "C2Loop: attempting blockchain C2 resolution" ascii //weight: 1
        $x_1_5 = "C2Loop: blockchain resolved C2" ascii //weight: 1
        $x_1_6 = "Keylog: key state initialized" ascii //weight: 1
        $x_1_7 = "KeylogPollOnce: KEY DETECTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

