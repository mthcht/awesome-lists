rule Ransom_MSIL_Rebud_2147725270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Rebud"
        threat_id = "2147725270"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rebud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "50249CB817A0AE06797751DC5D00656CAD86C8EA" ascii //weight: 2
        $x_2_2 = "C:\\Users\\Ciara&Cody\\Desktop\\DUMB-master\\DUMB\\obj\\Release\\DUMB.pdb" ascii //weight: 2
        $x_2_3 = "1CRYPTWALKERcVysimeMnMxThLLtpsnVbbz3VoJTy" wide //weight: 2
        $x_2_4 = "You have been struck with CRYPTWALKER" wide //weight: 2
        $x_2_5 = "Your files have been encrypted," wide //weight: 2
        $x_2_6 = "in fourty-eight hours the key to decrypt your files will be deleted" wide //weight: 2
        $x_2_7 = "deposit 0.5 Bitcoins into our private bitcoino wallet." wide //weight: 2
        $x_2_8 = "18PQPTh8xCykVdXRty9kkkMkUWdeLsZ1Z4" wide //weight: 2
        $x_2_9 = "Put a folder in My Documents called 'TEST' and chuck any files you want to get fucked up" wide //weight: 2
        $x_2_10 = "next time read the god damn README" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

