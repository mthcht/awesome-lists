rule Spammer_Win32_VMailer_A_2147645054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/VMailer.A"
        threat_id = "2147645054"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "VMailer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Release\\mailermodule199.pdb" ascii //weight: 1
        $x_1_2 = "--- Batch of %d for domain %s" ascii //weight: 1
        $x_1_3 = "sentmails server=%s:%d listid=%u pid=%u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

