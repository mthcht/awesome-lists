rule Ransom_Win32_GOCoder_DA_2147939991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GOCoder.DA!MTB"
        threat_id = "2147939991"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GOCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "140"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Go build ID: \"gSdQx6U_kkPES295cEsM" ascii //weight: 100
        $x_10_2 = "Go/src/internal/chacha8rand/chacha8.go" ascii //weight: 10
        $x_10_3 = "crypto/internal/fips140/aes.EncryptionKeySchedule" ascii //weight: 10
        $x_10_4 = "crypto/internal/fips140/aes.encryptBlockAsm" ascii //weight: 10
        $x_10_5 = "_expand_key_" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

