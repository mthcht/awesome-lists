rule TrojanDownloader_Win32_WinosStager_DA_2147974724_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/WinosStager.DA!MTB"
        threat_id = "2147974724"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "WinosStager"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "n_204?atyp=csi&ei=Pj4WarvAJqSYvr0Pk4SD2Ao&s=jsa&jsi=hd,st.6549,t.0,at.1,et.cl" wide //weight: 1
        $x_1_2 = {69 6c b2 ff 66 6a b2 ff 66 6a b2 ff 5b 60 b0 ff 5e 63 b2 ff 59 5e a8 ff 5f 63 ab ff 65 69 b0 ff 58 5c a4 ff 65 69 b1 ff 68 6b b3 ff 66 6a b2 ff 67 6b b2 ff 67 6a b2 ff 67 6b b3 ff 65 69 b1 ff 5a 5f ac ff 58 5d ab ff 58 5e ab ff 59 5e ac ff 58 5e ac ff 58 5e ab ff 58 5e ab ff 58 5e ac ff 58 5e ab ff 58 5e ad ff 58 5e ab ff 5c 61 b0 ff 51 57 a9 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

