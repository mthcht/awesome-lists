rule Trojan_MSIL_CryptOne_A_2147907784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptOne.A!MTB"
        threat_id = "2147907784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptOne"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "for ($count = 0; $count -lt $Bytes.Count; $count++)" wide //weight: 2
        $x_2_2 = "[Byte]$b = $Bytes[$count]" wide //weight: 2
        $x_2_3 = "$count + 1) -eq $Bytes.Length" wide //weight: 2
        $x_2_4 = "+= \"0x{0:x2}\" -f $" wide //weight: 2
        $x_2_5 = "$count + 1) % 15 -eq 0" wide //weight: 2
        $x_2_6 = "+= \"{0}\" -f" wide //weight: 2
        $x_2_7 = "[System.Text.Encoding]::Unicode.GetString($" wide //weight: 2
        $x_2_8 = "Invoke-Expression -Command $" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

