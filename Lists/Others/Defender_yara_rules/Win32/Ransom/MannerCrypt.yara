rule Ransom_Win32_MannerCrypt_MK_2147851638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MannerCrypt.MK!MTB"
        threat_id = "2147851638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MannerCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\QQMusicModel\\vcruntime140\\Release\\vcruntime140.pdb" ascii //weight: 1
        $x_1_2 = "All your files are encrypted by me!" ascii //weight: 1
        $x_1_3 = "Please pay a ransom of 100USDT to me!" ascii //weight: 1
        $x_1_4 = "Otherwise, your files cannot be decrypted even if God comes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

