<?php
include '../src/Upload.php';

use Farisc0de\PhpFileUploading\Upload;

$upload = new Upload();

$upload->setController('../src/');

$upload->setUploadFolder([
    'folder_name' => 'uploads',
    'folder_path' => realpath('uploads')
]);

$upload->enableProtection();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $upload->setUpload($_FILES['file']);

    if ($upload->checkIfNotEmpty()) {
        if (!$upload->checkForbidden()) {
            echo "Forbidden name";
            exit;
        }

        if (!$upload->checkExtension()) {
            echo "Forbidden Extension";
            exit;
        }

        if (!$upload->checkMime()) {
            echo "Forbidden Mime";
            exit;
        }

        if (!$upload->isImage()) {
            echo "Not Image";
            exit;
        }

        $upload->hashName();

        $upload->upload();

        $data = json_decode($upload->getJSON(), true);
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Uploading Service</title>
</head>

<body>
    <?php if (isset($data)) : ?>
        <p>You file has been uploaded</p>
    <?php endif; ?>

    <form action="" method="post" enctype="multipart/form-data">
        <input type="file" name="file" id="file">
        <button type="submit">Upload</button>
    </form>

    <div>
        <ul>
            <li>Filename: <?= $data['filename']; ?></li>
            <li>Filehash: <?= $data['filehash']; ?></li>
            <li>Filesize: <?= $data['filesize']; ?></li>
            <li>Upload at: <?= $data['uploaddate']; ?></li>
        </ul>
    </div>
</body>

</html>