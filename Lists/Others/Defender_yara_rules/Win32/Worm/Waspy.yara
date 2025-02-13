rule Worm_Win32_Waspy_A_2147617380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Waspy.A"
        threat_id = "2147617380"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Waspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Microsoft\\windows\\currentversion\\run\\mab" wide //weight: 1
        $x_1_2 = "Sorry!!!! $%%#@&re*$%$rthn#$^&&!f#&%$$f$#df#@^%$~`<:JHFgYttrt" wide //weight: 1
        $x_1_3 = {2e 00 68 00 74 00 6d 00 6c 00 [0-10] 2e 00 74 00 78 00 74 00 [0-10] 2e 00 64 00 6f 00 63 00 [0-10] 2e 00 78 00 6c 00 73 00 [0-10] 2e 00 63 00 70 00 70 00 [0-10] 2e 00 68 00 74 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

