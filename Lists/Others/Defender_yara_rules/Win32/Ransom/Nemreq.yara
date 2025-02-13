rule Ransom_Win32_Nemreq_A_2147711954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nemreq.A"
        threat_id = "2147711954"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nemreq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 75 62 6d 69 74 3d 73 75 62 6d 69 74 26 69 64 3d 25 73 26 67 75 69 64 3d 25 73 26 70 63 3d 25 73 26 6d 61 69 6c 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "DECRYPT FILES EMAIL" wide //weight: 1
        $x_1_4 = "Global\\snc_" wide //weight: 1
        $x_1_5 = "How to decrypt your files.txt" wide //weight: 1
        $x_1_6 = "doc(.doc;.docx;.pdf;.xls;.xlsx;.ppt;)" wide //weight: 1
        $x_1_7 = ";Decryption instructions.jpg;Decryptions instructions.txt;" wide //weight: 1
        $x_1_8 = "C:\\crysis\\Release\\PDB\\payload.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

