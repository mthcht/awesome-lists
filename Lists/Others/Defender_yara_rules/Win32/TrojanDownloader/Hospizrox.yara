rule TrojanDownloader_Win32_Hospizrox_A_2147706846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Hospizrox.A"
        threat_id = "2147706846"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Hospizrox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "A13B9E22A3EC2D6DAFEE127192F31A799BE12B68AAD031B739599C3391334A8CC8C773ED6F" ascii //weight: 4
        $x_4_2 = "084184C90B7492F0558F35ABED10779DFF090F7496FC1ABB1FBF074185C509438380C60B0B4F89CC03035DFA6FEA5184D87D9DD41957B7104F82D67E9D3F9636" ascii //weight: 4
        $x_4_3 = "B62E933998E32260A0E12764A7E62F6CACD03857BBC3C328494991C3175587C11F7CC70041" ascii //weight: 4
        $x_4_4 = "2459F35041AD30B5394B91D80702135F85E60277F777FF6B85E473AEFF6AF0758CEE067AF775E32170FA7FE2046181F50663F12F7EE81E5693E91F5590ED7A9786D" ascii //weight: 4
        $x_2_5 = "56BCC5CC2052B8D82053B9DB216494E71D7FF304087A9FE1285BA2E5196B95E81A" ascii //weight: 2
        $x_1_6 = "0D7096FF7599F80B0E7196FD07798A" ascii //weight: 1
        $x_1_7 = "37A92BAA3EAE1242" ascii //weight: 1
        $x_1_8 = "D2274281D9" ascii //weight: 1
        $x_1_9 = "829DFE18" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

