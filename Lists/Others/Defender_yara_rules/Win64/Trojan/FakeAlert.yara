rule Trojan_Win64_FakeAlert_A_2147980565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeAlert.A!MTB"
        threat_id = "2147980565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeAlert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_40_1 = "Step 3b: Payload URL built" ascii //weight: 40
        $x_30_2 = "ERROR: CreateProcessW for payload failed" ascii //weight: 30
        $x_20_3 = "Step 2c: Launching detached process..." ascii //weight: 20
        $x_10_4 = "Step 2b: Self copy OK" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

