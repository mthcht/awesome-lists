rule Trojan_Win32_FakeHadoc_157710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeHadoc"
        threat_id = "157710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeHadoc"
        severity = "3"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 b8 10 00 e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 83 f8 ?? 7d 0c e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c0 8a 02 8b f3 40 85 c0 c1 f8 00 48 33 45 ?? 40 85 c0 c1 f8 00 48 48 40}  //weight: 2, accuracy: Low
        $x_1_3 = "8FAE9CAE-3F35-4F06-B034-0E1B4D8F6651" wide //weight: 1
        $x_1_4 = "HDD Doctor" ascii //weight: 1
        $x_1_5 = {5c 69 6e 73 74 61 6c 6c 5f 68 64 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

