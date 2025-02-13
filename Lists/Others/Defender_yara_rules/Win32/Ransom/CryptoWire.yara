rule Ransom_Win32_CryptoWire_2147751400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoWire!MSR"
        threat_id = "2147751400"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoWire"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 2
        $x_2_2 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 2
        $x_2_3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 2
        $x_1_4 = "Your files has been decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CryptoWire_S_2147751476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoWire.S!MTB"
        threat_id = "2147751476"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoWire" wide //weight: 1
        $x_1_2 = "FUNC _CRYPT_ENCRYPTFILE ( $SSOURCEFILE , $SDESTINATIONFILE , $VCRYPTKEY , $IALGID )" wide //weight: 1
        $x_1_3 = "The only way you can recover your files is to buy a decryption key" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_CryptoWire_MK_2147784328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoWire.MK!MTB"
        threat_id = "2147784328"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FOR $CW509 = 1 TO 5" wide //weight: 2
        $x_2_2 = "$CW = EXECUTE ( BINARYTOSTRING" wide //weight: 2
        $x_1_3 = "IF ISARRAY ( $CW ) AND $CW [ 0 ] >= 2078 THEN EXITLOOP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

