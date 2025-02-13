rule Ransom_Win32_CryptedAutoIt_S_2147751474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptedAutoIt.S!MTB"
        threat_id = "2147751474"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptedAutoIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_CRYPT_ENCRYPTFILE ( $FILE , $FILE & \".CRYPTED\" , $KEY , $CALG_AES_256 )" wide //weight: 1
        $x_1_2 = "$FILES = _FILELISTTOARRAYREC ( $PATH , \"*.CRYPTED\" , 1 , 1 , 0 , 2 )" wide //weight: 1
        $x_1_3 = "IF NOT STRINGINSTR ( $FILES [ $I ] , \".CRYPTED\" ) AND $SIZE < 50000 THEN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

