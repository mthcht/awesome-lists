rule Ransom_MSIL_Filecoder_A_2147731899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.A"
        threat_id = "2147731899"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Users\\dennis\\Desktop\\Software\\BSS_ransomware\\BSS_ransomware\\obj\\Debug\\BSS_ransomware.pdb" ascii //weight: 5
        $x_5_2 = "Send me some bitcoins or kebab" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_A_2147757635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.A!MTB"
        threat_id = "2147757635"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_2 = "reais em bitcoin para a carteira" wide //weight: 1
        $x_1_3 = "ENtre a chave para descriptografar" wide //weight: 1
        $x_1_4 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_5 = "Agora, que os jogos come" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_DU_2147759304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DU!MTB"
        threat_id = "2147759304"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BTC Address :" ascii //weight: 1
        $x_1_2 = "LOCKTHAT" ascii //weight: 1
        $x_1_3 = "SPLITTTT" ascii //weight: 1
        $x_1_4 = "stubAES.Resources" ascii //weight: 1
        $x_1_5 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_6 = ".dsfdsf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_Filecoder_DU_2147759304_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DU!MTB"
        threat_id = "2147759304"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Decrypting files" ascii //weight: 1
        $x_1_2 = "Close crypter" ascii //weight: 1
        $x_1_3 = "You Successfully Paid Part/All Of Your Outstanding Balance" ascii //weight: 1
        $x_1_4 = "http://www.fusionpak.xyz/mal/verify.php" ascii //weight: 1
        $x_1_5 = "Shouldnt Have Tried To Debug Our Software" ascii //weight: 1
        $x_1_6 = "$150 USD Remaining" ascii //weight: 1
        $x_1_7 = "Deposit Funds" ascii //weight: 1
        $x_1_8 = "C:\\Users\\Samb2\\Desktop\\DUMB-master\\DUMB\\obj\\Release\\DUMB.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_MSIL_Filecoder_MK_2147761624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MK!MTB"
        threat_id = "2147761624"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files on your computer" wide //weight: 1
        $x_1_2 = "personal decryption code" wide //weight: 1
        $x_1_3 = "keygroup777" wide //weight: 1
        $x_1_4 = "bitcoin" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_MK_2147761624_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MK!MTB"
        threat_id = "2147761624"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware" ascii //weight: 1
        $x_1_2 = "component/app.xaml" ascii //weight: 1
        $x_1_3 = "Hackeado Puta" ascii //weight: 1
        $x_1_4 = "CyptedReady.ini" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
        $x_1_6 = "component/mainwindow.xaml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_MK_2147761624_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MK!MTB"
        threat_id = "2147761624"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransome Ware" ascii //weight: 1
        $x_1_2 = "Ransome Ware.g.resources" ascii //weight: 1
        $x_1_3 = "Ransome_Ware.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Your Windows Computer Has Contracked" ascii //weight: 1
        $x_1_5 = "Cornao Virus Please Seand Diascord Nitro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_MK_2147761624_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MK!MTB"
        threat_id = "2147761624"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadME-Decrypt.txt" ascii //weight: 1
        $x_1_2 = "https://paxful.com" ascii //weight: 1
        $x_1_3 = "mailto:MREncptor@protonmail.com" ascii //weight: 1
        $x_1_4 = "All your information is locked With Strong Randsomware" ascii //weight: 1
        $x_1_5 = "We only Accept Bitcoin" ascii //weight: 1
        $x_1_6 = "Cost For Your All Data Decrypt" ascii //weight: 1
        $x_1_7 = "You Are Crypted" ascii //weight: 1
        $x_1_8 = "All your data has been locked us" ascii //weight: 1
        $x_1_9 = "We Will Delete Your Decrypt Key" ascii //weight: 1
        $x_1_10 = "No Money ! No Decryption" ascii //weight: 1
        $x_1_11 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_MSIL_Filecoder_DA_2147762108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DA!MTB"
        threat_id = "2147762108"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cuteRansomware" ascii //weight: 1
        $x_1_2 = "secret.txt" ascii //weight: 1
        $x_1_3 = "Ransomware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DA_2147762108_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DA!MTB"
        threat_id = "2147762108"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RANSOM_FILENAME" ascii //weight: 1
        $x_1_2 = "RANSOM_NOTE" ascii //weight: 1
        $x_1_3 = "Fuck_You" ascii //weight: 1
        $x_1_4 = "Ransomware Test" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_MSIL_Filecoder_DA_2147762108_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DA!MTB"
        threat_id = "2147762108"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware2.0" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "SC_Ransom" ascii //weight: 1
        $x_1_4 = "Ransomware2._0.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_DA_2147762108_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DA!MTB"
        threat_id = "2147762108"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Now pay me the ransomware. BTC Address:" ascii //weight: 1
        $x_1_2 = "Your files are being encrypted" ascii //weight: 1
        $x_1_3 = "All of your files have been encrypted" ascii //weight: 1
        $x_1_4 = "To decrypt your files please enter the password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_DA_2147762108_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DA!MTB"
        threat_id = "2147762108"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Corona.pdb" ascii //weight: 1
        $x_1_2 = "Your personal files are being deleted. Your photos, videos, documents, etc..." ascii //weight: 1
        $x_1_3 = "Every hour I select some of them to delete permanently" ascii //weight: 1
        $x_1_4 = "you will get 1000 files deleted as a punishment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_DA_2147762108_5
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DA!MTB"
        threat_id = "2147762108"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cost to Decrypt" ascii //weight: 1
        $x_1_2 = "Encryption Complete" ascii //weight: 1
        $x_1_3 = "Your files are being encrypted" ascii //weight: 1
        $x_1_4 = "Please pay for decryption password" ascii //weight: 1
        $x_1_5 = "Do not close or you will lose your data" ascii //weight: 1
        $x_1_6 = "If you exit this program the encryption key will be destroyed" ascii //weight: 1
        $x_1_7 = "you will lose all of your data and the encryption key will be destroyed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_Filecoder_DB_2147762199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DB!MTB"
        threat_id = "2147762199"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are decrypted now" ascii //weight: 1
        $x_1_2 = ".PATPAT" ascii //weight: 1
        $x_1_3 = "headpats to go!" ascii //weight: 1
        $x_1_4 = "patpatware.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DB_2147762199_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DB!MTB"
        threat_id = "2147762199"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_2 = "Still locked. Just pay." ascii //weight: 1
        $x_1_3 = "Unlocked. Thanks for paying." ascii //weight: 1
        $x_1_4 = "P4YME" ascii //weight: 1
        $x_1_5 = "password.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DB_2147762199_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DB!MTB"
        threat_id = "2147762199"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Oops,your personal files have been encrypted!" ascii //weight: 1
        $x_1_2 = "Send $300 worth of bitcoin to this address:" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "MALWARE.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_DB_2147762199_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DB!MTB"
        threat_id = "2147762199"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypter.pdb" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "\\d78b6f30225cdc811adfe8d4e7c9fd34\\Encrypter.exe" ascii //weight: 1
        $x_1_4 = "\\d78b6f30225cdc811adfe8d4e7c9fd34\\Decrypter.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_DC_2147762301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DC!MTB"
        threat_id = "2147762301"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "._____TBTT_____" ascii //weight: 1
        $x_1_2 = "encryptor.Properties.Resources" ascii //weight: 1
        $x_1_3 = "FileCrypt" ascii //weight: 1
        $x_1_4 = "GenCUSTOMAESKey" ascii //weight: 1
        $x_1_5 = "encryptor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DC_2147762301_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DC!MTB"
        threat_id = "2147762301"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All of your files are decrypted" ascii //weight: 1
        $x_1_2 = "You cannot decrypt more files for free" ascii //weight: 1
        $x_1_3 = "To decrypt more, contact: programiletisim1@gmail.com" ascii //weight: 1
        $x_1_4 = ".zeronine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_SA_2147762630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SA!MTB"
        threat_id = "2147762630"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!!Readme!!!Help!!!.txt" ascii //weight: 1
        $x_1_2 = "data1992@protonmail.com" ascii //weight: 1
        $x_1_3 = "shutdown.exe" ascii //weight: 1
        $x_1_4 = "taskkill.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SA_2147762630_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SA!MTB"
        threat_id = "2147762630"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 09 11 0a 61 13 15 11 08 11 0f 11 15 20 ?? ?? ?? ?? 5f}  //weight: 2, accuracy: Low
        $x_2_2 = {58 11 15 20 00 00 ff 00 5f 1f 10 64 d2 9c 11 08 11 0f 19 58 11 15 20 ?? ?? ?? ?? 5f 1f 18 64 d2}  //weight: 2, accuracy: Low
        $x_1_3 = "U1OA9oWOyDJaui4H8n" ascii //weight: 1
        $x_1_4 = "xP3Jy4VUAVWGuE8Kmo" ascii //weight: 1
        $x_1_5 = "TPInFn4fE8pALN8q9lo" ascii //weight: 1
        $x_1_6 = "System.IO.Compression" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SA_2147762630_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SA!MTB"
        threat_id = "2147762630"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If you wanna support me, you can send me a beer money via cryptocurrency. Thanks a lot." ascii //weight: 1
        $x_1_2 = "There is no file!" ascii //weight: 1
        $x_1_3 = "File has been encrypted!" ascii //weight: 1
        $x_1_4 = "Please enter 1 byte lengt password!" ascii //weight: 1
        $x_1_5 = "Dont blank the path!" ascii //weight: 1
        $x_1_6 = "JonCrypt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PF_2147762645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PF!MTB"
        threat_id = "2147762645"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locked-padlock" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "Looks like your files have been encrypted" ascii //weight: 1
        $x_1_4 = "\\Desktop\\README.txt" ascii //weight: 1
        $x_1_5 = "C:\\Windows\\Logs\\kekw.exe" ascii //weight: 1
        $x_1_6 = "https://cdn.discordapp.com/attachments/734517412287873038/746088022356918463/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_Filecoder_DI_2147764611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DI!MTB"
        threat_id = "2147764611"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "password123" ascii //weight: 1
        $x_1_4 = "SC_Ransom" ascii //weight: 1
        $x_1_5 = "FileCrypter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_DI_2147764611_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DI!MTB"
        threat_id = "2147764611"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES ARE ENCRYPTED!" ascii //weight: 1
        $x_1_2 = ".Dusk" ascii //weight: 1
        $x_1_3 = "Do not waste your time trying recover your files using third party services! Only we can do that" ascii //weight: 1
        $x_1_4 = "Send $50 to this address:" ascii //weight: 1
        $x_1_5 = "cyber.duskfly@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_DJ_2147764626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DJ!MTB"
        threat_id = "2147764626"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REPLACE_COMMAND_LINE" ascii //weight: 1
        $x_1_2 = "\\system32\\cmstp.exe" ascii //weight: 1
        $x_1_3 = "CMSTPBypass" ascii //weight: 1
        $x_1_4 = "GetRandomFileName" ascii //weight: 1
        $x_1_5 = "ig.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DJ_2147764626_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DJ!MTB"
        threat_id = "2147764626"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files hve been encrypted" ascii //weight: 1
        $x_1_2 = "Start Ransomware" ascii //weight: 1
        $x_1_3 = "DeletedItems.txt" ascii //weight: 1
        $x_1_4 = "DO NOT DELETE THIS FILE!! THIS FILE IS USED FOR DECRYPTION" ascii //weight: 1
        $x_1_5 = "files encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_DK_2147764701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DK!MTB"
        threat_id = "2147764701"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Looks like your files are encrypted" ascii //weight: 1
        $x_1_2 = "Kill switch activated!" ascii //weight: 1
        $x_1_3 = "Starting fake svchost.exe..." ascii //weight: 1
        $x_1_4 = "Infecting computer..." ascii //weight: 1
        $x_1_5 = "i will remove your key for your encrypted files which means that your files are gone!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_DL_2147764702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DL!MTB"
        threat_id = "2147764702"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW_TO_DECYPHER_FILES.txt" ascii //weight: 1
        $x_1_2 = "HOW_TO_DECYPHER_FILES.hta" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "taskkill.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DO_2147765612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DO!MTB"
        threat_id = "2147765612"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOU HAVE BEEN ATTACKED. PLEASE CONTACT ON THIS EMAIL IF YOU WANT TO GET YOUR FILES BACK." ascii //weight: 1
        $x_1_2 = "T3chZ0n3@1234" ascii //weight: 1
        $x_1_3 = "encrypt.exe" ascii //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PG_2147766560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PG!MTB"
        threat_id = "2147766560"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoRansomware" wide //weight: 1
        $x_1_2 = "C:\\Users\\houcemjouini\\Desktop\\projet sans fils\\test" wide //weight: 1
        $x_1_3 = "Your all files are encrypted" wide //weight: 1
        $x_1_4 = "\\CryptoSomware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DP_2147766798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DP!MTB"
        threat_id = "2147766798"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransomware.pdb" ascii //weight: 1
        $x_1_2 = "ransomware.exe" ascii //weight: 1
        $x_1_3 = "ransomware.g.resources" ascii //weight: 1
        $x_1_4 = "ransomware_or_somethink_idk" ascii //weight: 1
        $x_1_5 = "ransomware.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DQ_2147766856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DQ!MTB"
        threat_id = "2147766856"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DO NOT RUN ANY ANTI-VIRUS PROGRAM" ascii //weight: 1
        $x_1_2 = "DURING DECRYPTION, DO NOT OPEN ANY DAMAGED FILE" ascii //weight: 1
        $x_1_3 = "DO NOT TRY TO DECRYPT FILES WITH ANOTHER PROGRAM" ascii //weight: 1
        $x_1_4 = "DO NOT CHANGE THE EXTENSION OF THE ENCRYPTED FILES" ascii //weight: 1
        $x_1_5 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_6 = "I'm running in Debug mode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DR_2147767072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DR!MTB"
        threat_id = "2147767072"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptFileSystem" ascii //weight: 1
        $x_1_2 = "EncryptionKey" ascii //weight: 1
        $x_1_3 = "install\\obj\\Release\\install.pdb" ascii //weight: 1
        $x_1_4 = "Users\\Public\\pay.jpg" ascii //weight: 1
        $x_1_5 = ".crypted" ascii //weight: 1
        $x_1_6 = "Ivan Medvedev" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DS_2147767073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DS!MTB"
        threat_id = "2147767073"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransomback.png" ascii //weight: 1
        $x_1_2 = "UpdateDecrypter.exe" ascii //weight: 1
        $x_1_3 = ".crypt" ascii //weight: 1
        $x_1_4 = "ransomupdate" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DD_2147768061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DD!MTB"
        threat_id = "2147768061"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "userPrivateIdKey.txt" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = "Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DD_2147768061_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DD!MTB"
        threat_id = "2147768061"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UnluckyWare.exe" ascii //weight: 1
        $x_1_2 = "Bytelocker.Properties" ascii //weight: 1
        $x_1_3 = "EncryptedFilesList" ascii //weight: 1
        $x_1_4 = "VW5sdWNreVdhcmUk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DD_2147768061_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DD!MTB"
        threat_id = "2147768061"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@READ_ME@.txt" ascii //weight: 1
        $x_1_2 = "Hello , all your files get encrypted !" ascii //weight: 1
        $x_1_3 = "ransomware.exe" ascii //weight: 1
        $x_1_4 = "wal.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DD_2147768061_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DD!MTB"
        threat_id = "2147768061"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW_TO_DECYPHER_FILES" ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_1_3 = "RGVsZXRlIFNoYWRvd3MgL2FsbCAvcXVpZXQ" ascii //weight: 1
        $x_1_4 = "c3RvcCDigJxTb3Bob3MgQXV0b1VwZGF0ZSBTZXJ2aWNl4oCdIC95" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DD_2147768061_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DD!MTB"
        threat_id = "2147768061"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".crypted" ascii //weight: 1
        $x_1_2 = "Ransomware Demonstration.exe" ascii //weight: 1
        $x_1_3 = "RansomwareDemonstration.Properties.Resources" ascii //weight: 1
        $x_1_4 = "This is a demonstration of ransomware applications. Do not use unethical" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_DW_2147768455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DW!MTB"
        threat_id = "2147768455"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Instructions.txt" ascii //weight: 1
        $x_1_2 = "all your desktop files have been encrypted!" ascii //weight: 1
        $x_1_3 = "RIP Your personal files if you dont pay..." ascii //weight: 1
        $x_1_4 = {54 6f 20 64 65 63 72 79 70 74 2c 20 73 65 6e 64 20 24 [0-4] 20 74 6f 20 74 68 65 20 62 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 3a}  //weight: 1, accuracy: Low
        $x_1_5 = ".himr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_DT_2147768780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DT!MTB"
        threat_id = "2147768780"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$22a02949-f613-4d29-acb6-151c574c8339" ascii //weight: 5
        $x_5_2 = "encTest.exe" ascii //weight: 5
        $x_5_3 = "BMI DataSender" ascii //weight: 5
        $x_2_4 = "r2block_Wallpaper.jpg" ascii //weight: 2
        $x_2_5 = "r2bWallpaper.jpg" ascii //weight: 2
        $x_1_6 = "BMI DataSender.pdb" ascii //weight: 1
        $x_1_7 = "!22222222222222222222222222222222222222222222222222" ascii //weight: 1
        $x_1_8 = "encTest.pdb" ascii //weight: 1
        $x_1_9 = ".r2bbb.rar.zip.exe.dll.cub.iso.vdi.msi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_DZ_2147769062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.DZ!MTB"
        threat_id = "2147769062"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files are encrypted" ascii //weight: 1
        $x_1_2 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_3 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_4 = "Encrypt2" ascii //weight: 1
        $x_1_5 = "@protonmail.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EB_2147769557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EB!MTB"
        threat_id = "2147769557"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Select Key and Decrypt!" ascii //weight: 1
        $x_1_3 = "CHOOSE YOUR KEYFILE.txt" ascii //weight: 1
        $x_1_4 = ".beethoven" ascii //weight: 1
        $x_1_5 = "@yandex.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EC_2147769558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EC!MTB"
        threat_id = "2147769558"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware2.0" ascii //weight: 1
        $x_1_2 = "Ransomware2._0.Properties.Resources" ascii //weight: 1
        $x_1_3 = "Your key worked all files are now decrypted !" ascii //weight: 1
        $x_1_4 = "Incorrect key make sure you buy a key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ED_2147769692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ED!MTB"
        threat_id = "2147769692"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uh oh, your files are encrypted!" ascii //weight: 1
        $x_1_2 = "Ransom_Note" ascii //weight: 1
        $x_1_3 = "DisableTaskmgr" ascii //weight: 1
        $x_1_4 = "The decryption key provided is incorrect" ascii //weight: 1
        $x_1_5 = "Decrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EE_2147769856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EE!MTB"
        threat_id = "2147769856"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Select * from Win32_ComputerSystem" ascii //weight: 1
        $x_1_2 = "SELECT * FROM Win32_NetworkAdapterConfiguration" ascii //weight: 1
        $x_1_3 = "HOW_TO_DECYPHER_FILES" ascii //weight: 1
        $x_1_4 = ".locked" ascii //weight: 1
        $x_1_5 = "TnVtYmVyIG9mIGZpbGVzIGVuY3J5cHRlZDog" ascii //weight: 1
        $x_1_6 = "UG9zc2libGUgYWZmZWN0ZWQgZmlsZXM6IA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EF_2147769857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EF!MTB"
        threat_id = "2147769857"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Locker.exe" ascii //weight: 1
        $x_1_2 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_3 = "Emergency file protction tool" ascii //weight: 1
        $x_1_4 = "84s)UHg-)IPSvAn:R#f80gi(.resources" ascii //weight: 1
        $x_1_5 = "SNg'G9h\\]\\[vSUuq9qJOkk$(SS!.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EG_2147769950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EG!MTB"
        threat_id = "2147769950"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "READ_ME.html" ascii //weight: 1
        $x_1_2 = "http://trustmordor.pw/readme.php?id=" ascii //weight: 1
        $x_1_3 = "NOTHERSPACE_USE.Properties.Resources" ascii //weight: 1
        $x_1_4 = "Web\\crypt\\joise\\obj\\Debug\\NOTHERSPACE_USE.pdb" ascii //weight: 1
        $x_1_5 = "NOTHERSPACE_USE.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EH_2147770167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EH!MTB"
        threat_id = "2147770167"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0.exe" ascii //weight: 1
        $x_1_2 = "FreezeMouse" ascii //weight: 1
        $x_1_3 = "Rasomware2._0.Properties" ascii //weight: 1
        $x_1_4 = "Rasomware2.0.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EI_2147770240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EI!MTB"
        threat_id = "2147770240"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Povlsomware" ascii //weight: 1
        $x_1_2 = "Win32_ShadowCopy" ascii //weight: 1
        $x_1_3 = "Decrypted:" ascii //weight: 1
        $x_1_4 = "Encrypted:" ascii //weight: 1
        $x_1_5 = "love.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EJ_2147770350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EJ!MTB"
        threat_id = "2147770350"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DISK_ENCODER.exe" ascii //weight: 1
        $x_1_2 = "DISK_ENCODER.pdb" ascii //weight: 1
        $x_1_3 = "ENCRYPTED" ascii //weight: 1
        $x_1_4 = "ENCRYPTEDD" ascii //weight: 1
        $x_1_5 = "GET_CIPHER_KEY" ascii //weight: 1
        $x_1_6 = ".fmfgmfgm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_Filecoder_EK_2147770413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EK!MTB"
        threat_id = "2147770413"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QWxsIHlvdXIgZmlsZXMgd2VyZSBlbmNyeXB0ZWQ" ascii //weight: 1
        $x_1_2 = "directoryWalker" ascii //weight: 1
        $x_1_3 = "get_FileParser" ascii //weight: 1
        $x_1_4 = "get_EncryptionKey" ascii //weight: 1
        $x_1_5 = "CreateEncryptionKey" ascii //weight: 1
        $x_1_6 = "WriteMessageToDocuments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EL_2147770414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EL!MTB"
        threat_id = "2147770414"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deReadMe!!!.txt" ascii //weight: 1
        $x_1_2 = "kill.bat" ascii //weight: 1
        $x_1_3 = "killme.bat" ascii //weight: 1
        $x_1_4 = "donot cry :)" ascii //weight: 1
        $x_1_5 = ".cring" ascii //weight: 1
        $x_1_6 = "Crypt3r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EM_2147770500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EM!MTB"
        threat_id = "2147770500"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@protonmail.ch" ascii //weight: 1
        $x_1_2 = "DECRYPT MY FILES" ascii //weight: 1
        $x_1_3 = "Encrypted.php" ascii //weight: 1
        $x_1_4 = "/C sc delete VSS" ascii //weight: 1
        $x_1_5 = "DecryptionInfo.auth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EN_2147770501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EN!MTB"
        threat_id = "2147770501"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "READ_ME.html" ascii //weight: 1
        $x_1_2 = ".onion.cab/data.php" ascii //weight: 1
        $x_1_3 = "NOTHERSPACE_USE.pdb" ascii //weight: 1
        $x_1_4 = "NOTHERSPACE_USE.Properties" ascii //weight: 1
        $x_1_5 = "NOTHERSPACE_USE.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EP_2147771125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EP!MTB"
        threat_id = "2147771125"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your Pc is Hacked" ascii //weight: 1
        $x_1_2 = "test.txt" ascii //weight: 1
        $x_1_3 = "Message to be written in test.txt" ascii //weight: 1
        $x_1_4 = "erawosnar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EQ_2147771126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EQ!MTB"
        threat_id = "2147771126"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files have been encrypted" ascii //weight: 1
        $x_1_2 = "Povlsomware 2.0" ascii //weight: 1
        $x_1_3 = "Win32_ShadowCopy" ascii //weight: 1
        $x_1_4 = "All your files belong to us!" ascii //weight: 1
        $x_1_5 = "@forgetit.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_ER_2147771273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ER!MTB"
        threat_id = "2147771273"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locked.zip" ascii //weight: 1
        $x_1_2 = "test.txt" ascii //weight: 1
        $x_1_3 = "Ionic.Zlib" ascii //weight: 1
        $x_1_4 = "Build.exe" ascii //weight: 1
        $x_1_5 = "set_Encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ES_2147771414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ES!MTB"
        threat_id = "2147771414"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BC_Logo_" ascii //weight: 1
        $x_1_2 = "Bitcoin" ascii //weight: 1
        $x_1_3 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_4 = "always_encrypted" ascii //weight: 1
        $x_1_5 = "GetEncryptedFiles" ascii //weight: 1
        $x_1_6 = "AlbCry" ascii //weight: 1
        $x_1_7 = "AlbCry 2.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_MSIL_Filecoder_ET_2147771415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ET!MTB"
        threat_id = "2147771415"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Great job, I'm decrypting your files" ascii //weight: 1
        $x_1_2 = "CLOSE TASK MANAGER NOW!" ascii //weight: 1
        $x_1_3 = "ExtensionsToEncrypt" ascii //weight: 1
        $x_1_4 = "@protonmail.com" ascii //weight: 1
        $x_1_5 = "DECRYPT ALL FILES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EU_2147771416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EU!MTB"
        threat_id = "2147771416"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware.Properties.Resources" ascii //weight: 1
        $x_1_2 = "getRandomFileName" ascii //weight: 1
        $x_1_3 = "aesKey" ascii //weight: 1
        $x_1_4 = "byte_ciphertext" ascii //weight: 1
        $x_1_5 = "encryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EV_2147771417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EV!MTB"
        threat_id = "2147771417"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "cuteRansomware" ascii //weight: 6
        $x_6_2 = "Razy_5._0.Ransomware" ascii //weight: 6
        $x_1_3 = "sendBack.txt" ascii //weight: 1
        $x_1_4 = "encryptAll" ascii //weight: 1
        $x_1_5 = "encryptFile" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "getRandomFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_EW_2147771974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EW!MTB"
        threat_id = "2147771974"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted." ascii //weight: 1
        $x_1_2 = "password123" ascii //weight: 1
        $x_1_3 = "Rasomware2.0" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EX_2147771975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EX!MTB"
        threat_id = "2147771975"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Background Ransom" ascii //weight: 1
        $x_1_2 = "preventchangedesktop.bat" ascii //weight: 1
        $x_1_3 = "ransomware.exe" ascii //weight: 1
        $x_1_4 = "Let_sBuildRansom.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EY_2147771976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EY!MTB"
        threat_id = "2147771976"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files have been encrypted" ascii //weight: 1
        $x_1_2 = "Povlsomware" ascii //weight: 1
        $x_1_3 = "Encrypted:" ascii //weight: 1
        $x_1_4 = "Win32_ShadowCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EZ_2147771977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EZ!MTB"
        threat_id = "2147771977"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!README!.hta" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "lockfile" ascii //weight: 1
        $x_1_4 = "@tutanota.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EO_2147772091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EO!MTB"
        threat_id = "2147772091"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0RxwEQwgtkSWC9sNTT.exPcKrbSb12M75mfcs" ascii //weight: 1
        $x_1_2 = "MvfdfvKNUdwvxfpM4P.2vpl5uS9L0Q3cXZgoO" ascii //weight: 1
        $x_1_3 = "Gorgon.Properties.Resources" ascii //weight: 1
        $x_1_4 = "{11111-22222-20001-00000}" ascii //weight: 1
        $x_1_5 = "{11111-22222-10009-11112}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_FA_2147772128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FA!MTB"
        threat_id = "2147772128"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".wncry" ascii //weight: 1
        $x_1_2 = ".ZIEBF_4561drgf" ascii //weight: 1
        $x_1_3 = "temp10.png" ascii //weight: 1
        $x_1_4 = "B6541265123.Properties.Resources" ascii //weight: 1
        $x_1_5 = "B6541265123.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_FB_2147772129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FB!MTB"
        threat_id = "2147772129"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" ascii //weight: 1
        $x_1_2 = "Mammoti.Properties.Resources" ascii //weight: 1
        $x_1_3 = "mammoti.jpg" ascii //weight: 1
        $x_1_4 = "ALL FILES LOADED..." ascii //weight: 1
        $x_1_5 = "Brute Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_FC_2147772130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FC!MTB"
        threat_id = "2147772130"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0.exe" ascii //weight: 1
        $x_1_2 = "Rasomware2._0.Ransomware2.resources" ascii //weight: 1
        $x_1_3 = "Rasomware2._0.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_FF_2147772264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FF!MTB"
        threat_id = "2147772264"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your important files are encrypted" ascii //weight: 1
        $x_1_2 = "bitcoin to this adress" ascii //weight: 1
        $x_1_3 = "Can i recover my files?" ascii //weight: 1
        $x_1_4 = "Payment is accepted only in bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_FG_2147772266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FG!MTB"
        threat_id = "2147772266"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Rasomware2.0" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_FH_2147772267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FH!MTB"
        threat_id = "2147772267"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 6f 75 72 20 66 69 6c 65 73 20 [0-15] 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64}  //weight: 1, accuracy: Low
        $x_1_2 = "friendly.cyber.criminal" ascii //weight: 1
        $x_1_3 = "RECOVER__FILES" ascii //weight: 1
        $x_1_4 = "BitcoinAddress" ascii //weight: 1
        $x_1_5 = ".jcrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_FI_2147772268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FI!MTB"
        threat_id = "2147772268"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SystemFuckRansom" ascii //weight: 2
        $x_2_2 = "CreateEncryptor" ascii //weight: 2
        $x_1_3 = "All you important files are encrypted" ascii //weight: 1
        $x_1_4 = "Niros.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_FJ_2147772306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FJ!MTB"
        threat_id = "2147772306"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your files have been encrypted" ascii //weight: 1
        $x_1_2 = "@protonmail.com" ascii //weight: 1
        $x_1_3 = "BTC to the address" ascii //weight: 1
        $x_1_4 = "Decryption Proccess has begun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_FK_2147772854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.FK!MTB"
        threat_id = "2147772854"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GatewayIPAddressInformationCollection" ascii //weight: 1
        $x_1_2 = "m@ai@l.@ro@tb@la@u.@eu@" ascii //weight: 1
        $x_1_3 = "Cur@ren@tVer@sion\\R@un" ascii //weight: 1
        $x_1_4 = "uploadfile" ascii //weight: 1
        $x_1_5 = "GetDirectories" ascii //weight: 1
        $x_1_6 = "GetExtension" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SH_2147774142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SH!MTB"
        threat_id = "2147774142"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fileEncrypted" ascii //weight: 1
        $x_1_2 = "DecryptionFile" ascii //weight: 1
        $x_1_3 = "ransomware@gmail.com" ascii //weight: 1
        $x_1_4 = "KA RANSOMWARE" ascii //weight: 1
        $x_1_5 = {11 73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 00 0f 2f 00 72 00 20 00 2f 00 74 00 20 00 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PK_2147783939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PK!MSR"
        threat_id = "2147783939"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" ascii //weight: 2
        $x_1_2 = "----> All of your files have been encrypted <----" ascii //weight: 1
        $x_1_3 = "Your computer was infected with a ransomware virus" ascii //weight: 1
        $x_1_4 = "read_apis.txt" ascii //weight: 1
        $x_1_5 = "Your files have been encrypted" ascii //weight: 1
        $x_1_6 = "wbadmin delete catalog -quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_AM_2147821583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AM!MTB"
        threat_id = "2147821583"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your all important files in encrypted" wide //weight: 1
        $x_1_2 = "StopWarInUkraine Ransowmare" wide //weight: 1
        $x_1_3 = "lockuiransow" wide //weight: 1
        $x_1_4 = "StopWarInUkraineLocker" wide //weight: 1
        $x_1_5 = "Your PC is infected StopWarInUkraine Ransowmare" wide //weight: 1
        $x_1_6 = "lockfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AN_2147821624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AN!MTB"
        threat_id = "2147821624"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramData\\PenterWareDecryptor.txt" wide //weight: 1
        $x_1_2 = "echo j | del deleteMyProgram.bat" wide //weight: 1
        $x_1_3 = "HKLM\\SOFTWARE\\recfg\\sk_key" ascii //weight: 1
        $x_1_4 = "ynet.co.il" ascii //weight: 1
        $x_1_5 = "decryptionKey" wide //weight: 1
        $x_1_6 = "filesToDecrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EVI_2147821812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EVI!MTB"
        threat_id = "2147821812"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 46 75 63 6b 4d 65 6d 6f 72 79 4d 65 74 68 6f 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 45 5a 49 50 36 34 5f 44 65 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 45 5a 49 50 36 34 5f 45 6e 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_4 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_5 = {00 44 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 6f 63 75 6d 65 6e 74 5f 46 75 63 6b 65 72 00}  //weight: 1, accuracy: High
        $x_1_7 = "files are encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_MA_2147822280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MA!MTB"
        threat_id = "2147822280"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 11 00 00 70 28 3a 00 00 06 7e 1e 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_MA_2147822280_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MA!MTB"
        threat_id = "2147822280"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 17 06 17 72 ?? ?? ?? 70 28 ?? ?? ?? 06 11 17 72 e9 00 00 70 28 ?? ?? ?? 0a 13 18 16 13 19 2b 44 11 19 17 58 13 19 11 18 17 8d ?? ?? ?? 01 25 16 1f 2e 9d}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\KF.RTK" wide //weight: 1
        $x_1_3 = "EncryptDecrypt" ascii //weight: 1
        $x_1_4 = "WriteNote" ascii //weight: 1
        $x_1_5 = "TODOS TUS ARCHIVOS FUERON CIFRADOS" wide //weight: 1
        $x_1_6 = "para descifrarlos debes enviar un correo a" wide //weight: 1
        $x_1_7 = "\\note.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_MA_2147822280_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MA!MTB"
        threat_id = "2147822280"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 06 6f ?? ?? ?? 0a 0c 03 19 73 ?? ?? ?? 0a 0d 73 ?? ?? ?? 0a 13 04 09 11 04 08 08 6f ?? ?? ?? 0a 16 73 ?? ?? ?? 0a 13 05 04 18 73 ?? ?? ?? 0a 13 06 2b 0b 11 06 11 07 d2 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 25 13 07 15 fe 01 16 fe 01 13 08 11 08 2d df}  //weight: 1, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_3 = "DisableTaskmgr" wide //weight: 1
        $x_1_4 = "DecryptFile" ascii //weight: 1
        $x_1_5 = "EncryptFiles" ascii //weight: 1
        $x_1_6 = "lockfile" wide //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_1_9 = "*.freeukraine" wide //weight: 1
        $x_1_10 = "Your all files in encrypted." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_MB_2147822941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.MB!MTB"
        threat_id = "2147822941"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 24 11 24 28 ?? ?? ?? 0a 13 25 00 11 25 13 26 16 13 27 2b 35 11 26 11 27 9a 13 28 00 00 07 11 28 11 28 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 06 00 11 28 28 ?? ?? ?? 0a 00 00 de 05}  //weight: 1, accuracy: Low
        $x_1_2 = {13 05 04 18 73 ?? ?? ?? 0a 13 06 2b 0b 11 06 11 07 d2 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 25 13 07 15 fe 01 16 fe 01 13 08 11 08 2d df}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Windows\\BSOD.exe" wide //weight: 1
        $x_1_4 = "DisableTaskMg" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_6 = "\\decrypted" wide //weight: 1
        $x_1_7 = "EncryptFile" ascii //weight: 1
        $x_1_8 = ".FABRICPLUS" wide //weight: 1
        $x_1_9 = "notvalidemailadress.ransom@gmail.com" wide //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_RPU_2147823850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.RPU!MTB"
        threat_id = "2147823850"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vietcombanks.tk" wide //weight: 1
        $x_1_2 = "Desktop\\README.txt" wide //weight: 1
        $x_1_3 = "Your files have been encrypted" wide //weight: 1
        $x_1_4 = "ahihi@ripyon.me" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ABL_2147827396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ABL!MTB"
        threat_id = "2147827396"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 00 11 08 08 fe 04 2d da}  //weight: 5, accuracy: High
        $x_1_2 = "CryptoStreamMode" ascii //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
        $x_1_4 = "GetFolderPath" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "Bitmap" ascii //weight: 1
        $x_1_8 = "DeflateStream" ascii //weight: 1
        $x_1_9 = "GetFiles" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "ReadAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PKA_2147832629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PKA!MTB"
        threat_id = "2147832629"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DecryptionFile" ascii //weight: 1
        $x_1_2 = "EncryptionFile" ascii //weight: 1
        $x_1_3 = "FreezeMouse" ascii //weight: 1
        $x_1_4 = "SavitarRW.exe" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" ascii //weight: 1
        $x_1_6 = "shutdown" ascii //weight: 1
        $x_10_7 = "a2dXfc4WaBVw" ascii //weight: 10
        $x_10_8 = "You can't deceive me" ascii //weight: 10
        $x_10_9 = "SavitarRW\\SavitarRW\\obj\\Debug\\SavitarRW.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_PKC_2147833178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PKC!MSR"
        threat_id = "2147833178"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" ascii //weight: 10
        $x_1_2 = "----- ALL YOUR FILES ARE ENCRYPTED ------ " ascii //weight: 1
        $x_10_3 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 10
        $x_10_4 = "wbadmin delete catalog -quiet" ascii //weight: 10
        $x_10_5 = "DisableTaskMgr" ascii //weight: 10
        $x_1_6 = "photos, databases and other important are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_AJ_2147834865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AJ!MTB"
        threat_id = "2147834865"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Don't Worry Friends, You Can Get All Your Files back!" wide //weight: 1
        $x_1_2 = "All Your Files Like Photos, Databases, Documents, And Other Important Things Are still here" wide //weight: 1
        $x_1_3 = "The Only Method To Recover Files Is By Purchasing A Decryption Tool And Unique Key For You" wide //weight: 1
        $x_1_4 = "This Software Will Decrypt All Your Encrypted Files" wide //weight: 1
        $x_1_5 = "The price of the private key and decryption software is $15.000" wide //weight: 1
        $x_1_6 = "Please Note That You Will Never Recover Your Data Without Payment" wide //weight: 1
        $x_1_7 = "ht@tp@s:/@/c@3@.y@ar@tt@dn.de@" wide //weight: 1
        $x_1_8 = "In Order To Get This Software, You Need To Write In Our Email" wide //weight: 1
        $x_1_9 = "SOFT@WA@RE\\@Mic@roso@ft\\Win@dows\\Cur@ren@tVer@sion\\R@un" wide //weight: 1
        $x_1_10 = "Crypt_Massage.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AK_2147835166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AK!MTB"
        threat_id = "2147835166"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Warning: By closing me, you destroy your files" wide //weight: 1
        $x_1_2 = "Please add the strings: encpassword and encextention" wide //weight: 1
        $x_1_3 = "3pCXo2piEd.exe" wide //weight: 1
        $x_1_4 = "Your computer files have been encrypted with a military-grade algorithm" wide //weight: 1
        $x_1_5 = "Spectre Decryptor" wide //weight: 1
        $x_1_6 = "Click the Payment channel and complete it" wide //weight: 1
        $x_1_7 = "Get your keys and enter it here. Finished! Now your data will be decrypted" wide //weight: 1
        $x_1_8 = "Decrypt Files" wide //weight: 1
        $x_1_9 = "The Key is invalid" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PU_2147838297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PU!MTB"
        threat_id = "2147838297"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".crpt" wide //weight: 1
        $x_1_2 = "\\!RESTORE!.txt" wide //weight: 1
        $x_1_3 = "\\wallpp.png" wide //weight: 1
        $x_1_4 = "permanently damage your files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAY_2147839015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAY!MTB"
        threat_id = "2147839015"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 91 25 07 61 13 05 02 58 20 ?? ?? ?? 00 5d 0b 06 08 25 17 58 0c 11 05 d2 9c 11 04 17 58 13 04 11 04 09 8e 69 32 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AVA_2147839139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AVA!MTB"
        threat_id = "2147839139"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 16 0c 2b 16 07 08 9a 28 ?? ?? ?? 06 2c 08 07 08 9a 28 ?? ?? ?? 0a 08 17 58 0c 08 07 8e 69 32 e4}  //weight: 2, accuracy: Low
        $x_1_2 = "GetFolderPath" ascii //weight: 1
        $x_1_3 = ".locked" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_GER_2147841809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.GER!MTB"
        threat_id = "2147841809"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "At the moment, your system is not protected" ascii //weight: 1
        $x_1_2 = "We can fix it and restore files." ascii //weight: 1
        $x_1_3 = "send a file to decrypt trial" ascii //weight: 1
        $x_1_4 = "Decryption.helper@aol.com" ascii //weight: 1
        $x_1_5 = "Decryption.help@cyberfear.com" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AA_2147843623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AA!MTB"
        threat_id = "2147843623"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Files encrypted:" ascii //weight: 20
        $x_1_2 = "encryptedFileCount" ascii //weight: 1
        $x_1_3 = "ENCRYPTED_FILE_EXTENSION" ascii //weight: 1
        $x_1_4 = "encryptFolderContents" ascii //weight: 1
        $x_20_5 = "EnCrypt.Properties.Resources" ascii //weight: 20
        $x_1_6 = "EnCrypt.pdb" ascii //weight: 1
        $x_1_7 = "EncryptPhone" ascii //weight: 1
        $x_1_8 = "EnCryptExeName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_ACO_2147844706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ACO!MTB"
        threat_id = "2147844706"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 0c 2b 22 07 08 72 99 0e 00 70 06 16 72 99 0e 00 70 28 5b 00 00 0a 6f 5c 00 00 0a 28 5d 00 00 0a 9d 08 17 58 0c 08 1f 10 32 d9}  //weight: 2, accuracy: High
        $x_1_2 = "Send $50 worth of bitcoin to this address" wide //weight: 1
        $x_1_3 = "Ooops, your files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAD_2147848610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAD!MTB"
        threat_id = "2147848610"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "insert your bicoin adress here" ascii //weight: 2
        $x_2_2 = "how to remove cryptolocker" ascii //weight: 2
        $x_2_3 = "Your Personal Files Are Encrypted!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAD_2147848610_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAD!MTB"
        threat_id = "2147848610"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "COLIN RANSOMWARE" ascii //weight: 2
        $x_2_2 = "fuckunes_face" ascii //weight: 2
        $x_2_3 = "bin\\RuntimeBrokerPY.exe" ascii //weight: 2
        $x_2_4 = "\\EncryptDecryptFiles\\obj\\Debug\\Colinware.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAD_2147848610_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAD!MTB"
        threat_id = "2147848610"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\___RECOVER__FILES__.Sology.txt" ascii //weight: 2
        $x_2_2 = "All of your files have been encrypted." ascii //weight: 2
        $x_2_3 = "31hSWoVdZJgxtaiSXRqbTsEwVNw2vvCQtY" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AFC_2147848922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AFC!MTB"
        threat_id = "2147848922"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 24 00 09 11 04 8f ?? ?? ?? 01 25 47 02 7e ?? ?? ?? 04 11 04 5a 28 ?? ?? ?? 06 d2 61 d2 52 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04}  //weight: 2, accuracy: Low
        $x_1_2 = "floxen\\source\\repos\\RanSom\\obj\\Debug\\RanSom.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AFI_2147850635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AFI!MTB"
        threat_id = "2147850635"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 14 07 08 9a 0d 02 7b 26 00 00 04 09 6f ?? ?? ?? 0a 08 17 58 0c 08 07 8e 69 32 e6 03 6f ?? ?? ?? 0a 0a 06 2c 20 06 13 04 16 0c 2b 12 11 04 08 9a 13 05 02 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAAR_2147850729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAAR!MTB"
        threat_id = "2147850729"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 8f 1a 00 00 01 25 47 02 7e 03 00 00 04 11 04 5a 28 ?? ?? ?? 06 d2 61 d2 52 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 05 11 05 2d cf}  //weight: 1, accuracy: Low
        $x_1_2 = "RanSom.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAAS_2147850730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAAS!MTB"
        threat_id = "2147850730"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lokkit v1\\Lokkit v1\\obj\\Release\\Lokkit v1.pdb" ascii //weight: 1
        $x_1_2 = "ransomLbl1" wide //weight: 1
        $x_1_3 = "Dear user, your files have become encrypted. They are now locked and can't be recovered until you pay our fee." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAE_2147850732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAE!MTB"
        threat_id = "2147850732"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All of your files are encrypted" ascii //weight: 2
        $x_2_2 = "To unlock your files" ascii //weight: 2
        $x_2_3 = "Just send me :" ascii //weight: 2
        $x_2_4 = "Bitcoin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAE_2147850732_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAE!MTB"
        threat_id = "2147850732"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hi you are hacked" ascii //weight: 2
        $x_2_2 = "All your files are encrypted" ascii //weight: 2
        $x_2_3 = "File encryption successful!" ascii //weight: 2
        $x_2_4 = "EncryptFile" ascii //weight: 2
        $x_2_5 = "RC4Encrypt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAAU_2147851361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAAU!MTB"
        threat_id = "2147851361"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RANSOMWARE.pdb" ascii //weight: 1
        $x_1_2 = "YOUR COMPUTER HAS BEEN LOCKED!" wide //weight: 1
        $x_1_3 = "CRYPT.CRYPTOLOCKER" wide //weight: 1
        $x_1_4 = "Example_RANSOMWARE.Encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAAV_2147851429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAAV!MTB"
        threat_id = "2147851429"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 09 2b 1a 11 07 11 09 11 07 11 09 91 06 11 09 06 8e 69 5d 91 61 d2 9c 11 09 17 58 13 09 11 09 11 08 32 e0}  //weight: 1, accuracy: High
        $x_1_2 = "your computer has been attacked by Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAAW_2147851430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAAW!MTB"
        threat_id = "2147851430"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 04 07 11 04 91 08 11 04 08 8e 69 5d 91 11 04 04 d6 08 8e 69 d6 1d 5f 62 d2 20 ff 00 00 00 5f 61 b4 9c 11 04 17 d6 13 04 11 04 09 31 d1}  //weight: 1, accuracy: High
        $x_1_2 = "DisableRegistryTools" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AYV_2147852625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AYV!MTB"
        threat_id = "2147852625"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 16 13 04 2b 17 09 11 04 9a 13 05 00 02 11 05 28 04 00 00 06 00 00 11 04 17 58 13 04 11 04 09 8e 69 32 e2}  //weight: 2, accuracy: High
        $x_1_2 = "\\Users\\hello\\OneDrive\\Bureau\\Ransomware\\Ransomware\\obj\\Debug\\Ransomware.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAF_2147900804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAF!MTB"
        threat_id = "2147900804"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\ShellLocker Ransomware\\ShellLocker\\ShellLocker\\bin\\ShellLocker.pdb" ascii //weight: 2
        $x_2_2 = "Keyboard hooked" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAF_2147900804_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAF!MTB"
        threat_id = "2147900804"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\startRans.bat" ascii //weight: 2
        $x_2_2 = "\\recoveryKey.txt" ascii //weight: 2
        $x_2_3 = "\\Programs\\Startup\\startVs.bat" ascii //weight: 2
        $x_2_4 = "\\windows\\system32\\shutdown /r /t 0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAF_2147900804_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAF!MTB"
        threat_id = "2147900804"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 9a 13 04 00 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 81 01 00 70 28 ?? ?? ?? 0a 13 05 11 05 2c 3d 00 72 8b 01 00 70 13 06 11 04 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 72 9d 01 00 70 28 ?? ?? ?? 0a 11 06 28 ?? ?? ?? 06 00 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 03 28 ?? ?? ?? 0a 00 00 00 09 17 58 0d 09 08 8e 69 32 96}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AK_2147903596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AK!ibt"
        threat_id = "2147903596"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_2 = "emd9alp4KEECE2UKTwURHn4WdgECYHZcWj54WBBGcno" ascii //weight: 1
        $x_1_3 = "NRJXcKmyFPSOwGWXNWCBCPDknzAiRpAK" ascii //weight: 1
        $x_1_4 = "HGVxBhJcXV8RZEBkBnlwaiAIaVAqfi1KDBtTVwt9WmA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARAG_2147904165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARAG!MTB"
        threat_id = "2147904165"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 06 08 91 03 08 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 08 17 58 0c 08 06 8e 69 32 e0}  //weight: 2, accuracy: Low
        $x_2_2 = "\\rounc.pdb" ascii //weight: 2
        $x_2_3 = "File has been encrypted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PADN_2147907029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PADN!MTB"
        threat_id = "2147907029"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Discord: twobt69 or lifeofacookie" wide //weight: 1
        $x_1_2 = "If skip the queue, add us on Discord and pay us via Paypal or Crypto." wide //weight: 1
        $x_1_3 = "optimum.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SGE_2147913816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SGE!MTB"
        threat_id = "2147913816"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DiscordWebhook" ascii //weight: 1
        $x_1_2 = "Find the Readme.html file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SLO_2147913911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SLO!MTB"
        threat_id = "2147913911"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dropRansomLetter" ascii //weight: 1
        $x_1_2 = "DisableShutdown" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "Your files have been encrypted!" wide //weight: 1
        $x_1_5 = "Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_6 = "lblBitcoinAmount" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Filecoder_AAW_2147914875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AAW!MTB"
        threat_id = "2147914875"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Files Have Been Encrypted :)" wide //weight: 2
        $x_2_2 = "Send ME Some $$$$ or it will be deleted." wide //weight: 2
        $x_2_3 = "alpacino.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAB_2147917928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAB!MTB"
        threat_id = "2147917928"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Your infected by the Yani Screenlocker" wide //weight: 3
        $x_3_2 = "Yani_ransomware.Properties.Resources" wide //weight: 3
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAB_2147917928_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAB!MTB"
        threat_id = "2147917928"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "You became victim of the keygroup777 RANSOMWARE!" wide //weight: 2
        $x_2_2 = "All your files are stolen and encrypted" wide //weight: 2
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_OOL_2147919110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.OOL!MTB"
        threat_id = "2147919110"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RANSOM_NOTE.txt" wide //weight: 1
        $x_1_2 = "Send $50,000 worth of Bitcoin to the address below " wide //weight: 1
        $x_1_3 = "Decryption Status: Infected" wide //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\cmd.exe /c vssadmin resize shadowstorage /for=<unit>: /on=<unit>: /maxsize=unbounded" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARA_2147920066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARA!MTB"
        threat_id = "2147920066"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files have been encrypted" wide //weight: 2
        $x_2_2 = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" wide //weight: 2
        $x_2_3 = "24 hours to transfer" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_ARA_2147920066_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.ARA!MTB"
        threat_id = "2147920066"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RansomwareHandler" ascii //weight: 2
        $x_2_2 = "EncryptFilesInDrive" ascii //weight: 2
        $x_2_3 = "EncryptFilesInDirectory" ascii //weight: 2
        $x_2_4 = "Victim" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAFP_2147920768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAFP!MTB"
        threat_id = "2147920768"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bazek Ransomware" ascii //weight: 1
        $x_1_2 = "Encrypts files and holds users for ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NIT_2147920895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NIT!MTB"
        threat_id = "2147920895"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "encryptionAesRsa" ascii //weight: 2
        $x_2_2 = "disableRecoveryMode" ascii //weight: 2
        $x_2_3 = "All of your files have been encrypted" wide //weight: 2
        $x_1_4 = "ransomware from your computer" wide //weight: 1
        $x_1_5 = "vssadmin delete shadows //all //quiet & wmic shadowcopy delete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_NIT_2147920895_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NIT!MTB"
        threat_id = "2147920895"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\source\\repos\\Morgan\\Morgan\\obj\\Release\\Morgan.pdb" ascii //weight: 2
        $x_2_2 = ".morgan" wide //weight: 2
        $x_2_3 = "FILE_EXTENSIONS" ascii //weight: 2
        $x_2_4 = "Your files are encrypted using AES" wide //weight: 2
        $x_1_5 = "SPIF_UPDATEINIFILE" wide //weight: 1
        $x_1_6 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_SUW_2147922722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SUW!MTB"
        threat_id = "2147922722"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Jasmin_Encrypter" ascii //weight: 2
        $x_2_2 = "$78c76961-8249-4efe-9de2-b6ef15a187f7" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SUA_2147922723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SUA!MTB"
        threat_id = "2147922723"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bazek Ransomware.pdb" ascii //weight: 2
        $x_2_2 = "Bazek Ransomware.exe" ascii //weight: 2
        $x_2_3 = "BazekGroup" ascii //weight: 2
        $x_1_4 = "Encrypts files and holds users for ransom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SUR_2147922724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SUR!MTB"
        threat_id = "2147922724"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CashCat.pdb" ascii //weight: 2
        $x_2_2 = "CashCat.exe" ascii //weight: 2
        $x_1_3 = "txtbox_Bitcoingaddess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWA_2147922725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWA!MTB"
        threat_id = "2147922725"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NOSU.pdb" ascii //weight: 2
        $x_1_2 = "NOSU.Resources.resources" ascii //weight: 1
        $x_1_3 = "The system was infected with the NOSU virus" wide //weight: 1
        $x_1_4 = "DisableAntiSpyware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWA_2147922725_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWA!MTB"
        threat_id = "2147922725"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EncryptAllFiles" ascii //weight: 2
        $x_1_2 = "$a2f9f38d-e329-406f-be02-94c940d59e3b" ascii //weight: 1
        $x_1_3 = "All of your files got encrypted!" wide //weight: 1
        $x_1_4 = "costura.telegram.bot.pdb.compressed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWA_2147922725_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWA!MTB"
        threat_id = "2147922725"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KILL_APPS_ENCRYPT_AGAIN" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_1_3 = "All your files are stolen and encrypted" wide //weight: 1
        $x_1_4 = "ENCRYPT_DATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_SWB_2147922726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWB!MTB"
        threat_id = "2147922726"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 06 16 06 8e 69 6f ?? 00 00 0a 13 09 11 09 2c 0b 11 08 06 16 11 09 6f ?? 00 00 0a 11 09 2d df}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAFT_2147922993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAFT!MTB"
        threat_id = "2147922993"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "XerinFuscator" ascii //weight: 2
        $x_2_2 = "K.G.B - Burhan Alassad" ascii //weight: 2
        $x_2_3 = "$32241ffd-bfa6-4501-98b1-a818b30c3de7" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAP_2147924246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAP!MTB"
        threat_id = "2147924246"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "infected by Cryptic" wide //weight: 4
        $x_2_2 = "Successfully encrypted" wide //weight: 2
        $x_2_3 = "Enter password to decrypt the files" wide //weight: 2
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "\\Downloads" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWF_2147925564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWF!MTB"
        threat_id = "2147925564"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$fe831e17-492b-4af2-b686-795c6fbcdf92" ascii //weight: 2
        $x_2_2 = "majordom\\client\\majordom\\majordom\\obj\\Debug\\majordom.pdb" ascii //weight: 2
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITE_2147925863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITE!MTB"
        threat_id = "2147925863"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 20 00 01 00 00 6f ?? 00 00 0a 09 20 80 00 00 00 6f ?? 00 00 0a 03 07 20 e8 03 00 00 73 0f 00 00 0a 13 04 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 17 6f ?? 00 00 0a 08 09 6f ?? 00 00 0a 17 73 17 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITE_2147925863_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITE!MTB"
        threat_id = "2147925863"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 9a 0c 73 12 00 00 06 0d 09 08 28 ?? 00 00 0a 6f ?? 00 00 0a 7d 0b 00 00 04 02 7b 02 00 00 04 09 fe 06 13 00 00 06 73 1b 00 00 0a 28 ?? 00 00 2b 2c 42 08 72 ?? 00 00 70 6f ?? 00 00 0a 2d 35 08 28 ?? 00 00 0a 13 04 02 11 04 72 ?? 00 00 70 28 ?? 00 00 06 13 05 08 11 05 28 ?? 00 00 0a 08 08 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a de 03 26 de 00 07 17 58 0b 07 06 8e 69 32 80}  //weight: 2, accuracy: Low
        $x_2_2 = {04 6f 22 00 00 0a 0a 03 8e 69 8d ?? 00 00 01 0b 16 0c 2b 13 07 08 03 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 03 8e 69 32 e7 07 2a}  //weight: 2, accuracy: Low
        $x_1_3 = "EncryptTargetFolders" ascii //weight: 1
        $x_1_4 = "XorEncryptDecrypt" ascii //weight: 1
        $x_1_5 = "KeegansRansomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITE_2147925863_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITE!MTB"
        threat_id = "2147925863"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 16 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f 1c 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {73 16 00 00 0a 25 72 ?? 01 00 70 6f ?? 00 00 0a 25 72 ?? 01 00 70 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 16}  //weight: 2, accuracy: Low
        $x_2_3 = {73 16 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 02 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 73 16 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 02 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 03 02 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_4 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_5 = "DisableWindowsRecoveryEnvironment" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITD_2147925865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITD!MTB"
        threat_id = "2147925865"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 07 09 16 11 05 6f ?? 00 00 0a 26 16 13 06 38 11 00 00 00 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 3f e5 ff ff ff 28 ?? 00 00 0a 09 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PPG_2147927162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PPG!MTB"
        threat_id = "2147927162"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OMGOMGOMGLV2PATCHER111==" wide //weight: 3
        $x_2_2 = "This folder protects against Ransomware" wide //weight: 2
        $x_1_3 = "do notdelete" wide //weight: 1
        $x_1_4 = "\\G Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWH_2147927258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWH!MTB"
        threat_id = "2147927258"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EncryptSystem" ascii //weight: 2
        $x_1_2 = "$b841c29a-f2d3-4a08-bb80-44315616d1c7" ascii //weight: 1
        $x_1_3 = "EnternalRed\\obj\\Debug\\JPG-Datei.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWH_2147927258_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWH!MTB"
        threat_id = "2147927258"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 72 2d 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 72 51 01 00 70 28 ?? 00 00 0a 26 72 51 01 00 70 17 28 ?? 00 00 0a 00 06 72 2d 01 00 70 28 ?? 00 00 0a 17 28 ?? 00 00 0a 00 08 72 c7 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 73 87 00 00 0a 13 05 11 05 72 01 02 00 70 6f ?? 00 00 0a 00 11 05 17 6f ?? 00 00 0a 00 11 05 72 11 02 00 70 08 72 a3 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWI_2147927262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWI!MTB"
        threat_id = "2147927262"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$6487ef15-8e15-4df5-9cdf-116bf28f9a0d" ascii //weight: 2
        $x_2_2 = "Your files have been encrypted" ascii //weight: 2
        $x_1_3 = "AlertaRansom" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Filecoder_SUX_2147928353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SUX!MTB"
        threat_id = "2147928353"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 17 58 16 0b 45 1b 00 00 00 00 00 00 00 6a fe ff ff 73 fe ff ff 82 fe ff ff 91 fe ff ff a0 fe ff ff ad fe ff ff b3 fe ff ff c1 fe ff ff cb fe ff ff f5 fe ff ff da fe ff ff f3 fe ff ff f6 fe ff ff 29 ff ff ff f8 fe ff ff 0e ff ff ff 1d ff ff ff 28 ff ff ff 38 ff ff ff 43 ff ff ff 51 ff ff ff 5f ff ff ff 6d ff ff ff 78 ff ff ff 83 ff ff ff 85 ff ff ff de 3a 08 0b 06 1f fe 30 03 17 2b 01 06 45 02 00 00 00 00 00 00 00 70 ff ff ff de 20 75 27 00 00 01 14 fe 03 06 16 fe 03 5f 07 16 fe 01 5f fe 11}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_SWY_2147928354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.SWY!MTB"
        threat_id = "2147928354"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 25 13 05 16 31 38 09 11 04 16 11 05 6f ?? 00 00 0a 07 6f ?? 00 00 0a 16 6a 31 23 06 07 6f ?? 00 00 0a 65 17 6f ?? 00 00 0a 26 06 07 6f ?? 00 00 0a 16 07 6f ?? 00 00 0a 69 6f ?? 00 00 0a 11 05 16 30 b0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AKK_2147932586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AKK!MTB"
        threat_id = "2147932586"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DisableTaskManager" ascii //weight: 2
        $x_2_2 = "DisableFirefoxDownloads" ascii //weight: 2
        $x_2_3 = "tcp://2.tcp.eu.ngrok.io" wide //weight: 2
        $x_2_4 = "$028d0421-0685-40c3-9b3f-02dffb1947eb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Filecoder_PAGM_2147937837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAGM!MTB"
        threat_id = "2147937837"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your files were encrypted, good luck, discord: xcrypter." wide //weight: 2
        $x_2_2 = ".xcrypt" wide //weight: 2
        $x_1_3 = "background" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAGN_2147937838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAGN!MTB"
        threat_id = "2147937838"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "All your files have been encrypted with some super RansomWare!!" wide //weight: 2
        $x_2_2 = ".RANSOM" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_PAGP_2147938307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.PAGP!MTB"
        threat_id = "2147938307"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wallpaper.bmp" wide //weight: 2
        $x_1_2 = "But why steal this software? no shame? DO NOT USE!" wide //weight: 1
        $x_2_3 = "Are you sure want to proceed open this software on unsupported platform? It may harm your computer. You have been warn!" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AKD_2147940700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AKD!MTB"
        threat_id = "2147940700"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 7b 12 00 00 04 72 2c 06 00 70 28 ?? 00 00 06 6f 4a 00 00 0a 72 3a 06 00 70 28 ?? 00 00 0a 6f 4a 00 00 0a 72 48 06 00 70 28 ?? 00 00 06 6f 4c 00 00 0a 6f 4d 00 00 0a 6f 4a 00 00 0a 72 52 06 00 70 72 66 06 00 70 6f 4a 00 00 0a 28 ?? 00 00 0a 11 09 17 d6 13 09}  //weight: 3, accuracy: Low
        $x_3_2 = {03 28 64 00 00 0a 0a 02 06 05 28 1a 00 00 06 0b 04 07 28 65 00 00 0a de 0e}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITB_2147941023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITB!MTB"
        threat_id = "2147941023"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 0b 00 00 0a 25 72 d3 00 00 70 6f ?? 00 00 0a 25 72 ed 00 00 70 6f ?? 00 00 0a 25 72 2d 00 00 70 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = {73 0b 00 00 0a 25 72 4d 01 00 70 6f ?? 00 00 0a 25 72 67 01 00 70 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_AFL_2147941812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.AFL!MTB"
        threat_id = "2147941812"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 07 20 00 01 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 03 04 20 50 c3 00 00 73 ?? 00 00 0a 0c 07 08 07 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITF_2147945122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITF!MTB"
        threat_id = "2147945122"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06}  //weight: 2, accuracy: Low
        $x_2_2 = {72 29 01 00 70 28 ?? 00 00 06 72 71 01 00 70 28 ?? 00 00 06 72 c5 01 00 70 28 ?? 00 00 06 72 01 02 00 70 28 ?? 00 00 06 72 41 02 00 70 28 ?? 00 00 06}  //weight: 2, accuracy: Low
        $x_1_3 = {7e 14 00 00 0a 72 2a 06 00 70 17 6f ?? 00 00 0a 0a 06 72 86 06 00 70 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a de 0a 06 2c 06 06 6f ?? 00 00 0a dc 72 a2 06 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 72 0e 07 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 de 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_NITF_2147945122_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.NITF!MTB"
        threat_id = "2147945122"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 72 77 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 21 11 04 72 87 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 0e 11 04 72 9f 00 00 70 28 ?? 00 00 0a 13 05 11 05 28 ?? 00 00 0a 2d 02 de 33 11 05 28 ?? 00 00 06 06 7b 0c 00 00 04 25 2d 18 26 06 06 fe 06 19 00 00 06 73 3b 00 00 0a 25 13 06 7d 0c 00 00 04 11 06 28 ?? 00 00 2b 26 de 03}  //weight: 3, accuracy: Low
        $x_3_2 = {05 00 00 11 02 72 ?? 01 00 70 6f ?? 00 00 0a 2d 79 02 72 ?? 01 00 70 6f ?? 00 00 0a 2d 6c 02 72 ?? 01 00 70 6f ?? 00 00 0a 2d 5f 02 72 ?? 01 00 70 6f ?? 00 00 0a 2d 52 02 73 43 00 00 0a 6f ?? 00 00 0a 0a 02 03 72 ?? 01 00 70 28 ?? 00 00 06 02 28 ?? 00 00 0a 72 ?? 01 00 70 28 ?? 00 00 0a 0b 02 72 ?? 01 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 07 28 ?? 00 00 0a 2d 10 07 7e 05 00 00 04 28 ?? 00 00 06 28 ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_2_3 = {07 00 00 11 28 ?? 00 00 06 28 ?? 00 00 0a 72 ?? 01 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 6f ?? 00 00 0a 1f 14 16 06 19 28 ?? 00 00 06 2d 0a 72 ?? 01 00 70 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Filecoder_EDK_2147945216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Filecoder.EDK!MTB"
        threat_id = "2147945216"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransomeware.ps1" ascii //weight: 1
        $x_1_2 = "DO NOT ignore this message" ascii //weight: 1
        $x_1_3 = "your files will be lost forever!" ascii //weight: 1
        $x_1_4 = "UniKeyNT.exe" ascii //weight: 1
        $x_1_5 = "getPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

