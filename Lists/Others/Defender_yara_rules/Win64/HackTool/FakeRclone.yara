rule HackTool_Win64_FakeRclone_A_2147840537_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/FakeRclone.A"
        threat_id = "2147840537"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeRclone"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "no refresh token found - run `rclone config reconnect`oauth2/google:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

