rule DoS_Win32_SonicVote_A_2147813997_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/SonicVote.A!dha"
        threat_id = "2147813997"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "SonicVote"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The only thing that we learn from new elections is we learned nothing from the old!\"</b></p>" ascii //weight: 1
        $x_1_2 = "<p>Thank you for your vote! All your files, documents, photoes, videos, databases etc. have been successfully encrypted!</p>" ascii //weight: 1
        $x_1_3 = "<p>Now your computer has a special ID:<b> </b></p>" ascii //weight: 1
        $x_1_4 = "<p>Do not try to decrypt then by yourself - it's impossible!" ascii //weight: 1
        $x_1_5 = "<p>It's just a business and we care only about getting benefits." ascii //weight: 1
        $x_1_6 = "The only way to get your files back is to contact us and get further instuctions." ascii //weight: 1
        $x_1_7 = "<p>To prove that we have a decryptor send us any encrypted file (less than 650 kbytes) and we'll send you it back being decrypted." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

