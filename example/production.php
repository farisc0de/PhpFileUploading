<?php

/**
 * Production-ready file upload example
 * 
 * This example demonstrates how to use all the new features together
 * for a secure, production-ready file upload system.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Farisc0de\PhpFileUploading\File;
use Farisc0de\PhpFileUploading\Utility;
use Farisc0de\PhpFileUploading\UploadManager;
use Farisc0de\PhpFileUploading\UploadResult;
use Farisc0de\PhpFileUploading\Storage\LocalStorage;
use Farisc0de\PhpFileUploading\Validation\ValidationChain;
use Farisc0de\PhpFileUploading\Validation\Validators\ExtensionValidator;
use Farisc0de\PhpFileUploading\Validation\Validators\MimeTypeValidator;
use Farisc0de\PhpFileUploading\Validation\Validators\SizeValidator;
use Farisc0de\PhpFileUploading\Validation\Validators\FilenameValidator;
use Farisc0de\PhpFileUploading\Validation\Validators\ImageDimensionValidator;
use Farisc0de\PhpFileUploading\RateLimiting\FileRateLimiter;
use Farisc0de\PhpFileUploading\Security\ClamAvScanner;
use Farisc0de\PhpFileUploading\Security\NullScanner;
use Farisc0de\PhpFileUploading\Events\EventDispatcher;
use Farisc0de\PhpFileUploading\Events\UploadEvents;
use Farisc0de\PhpFileUploading\Events\FileEvent;
use Farisc0de\PhpFileUploading\Logging\FileLogger;
use Farisc0de\PhpFileUploading\Logging\LogLevel;

// Configuration
$config = [
    'upload_dir' => __DIR__ . '/uploads',
    'public_url' => 'https://example.com/uploads',
    'log_file' => __DIR__ . '/logs/upload.log',
    'rate_limit_dir' => __DIR__ . '/rate_limits',
    'max_uploads_per_minute' => 10,
    'allowed_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'],
    'allowed_mimes' => [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    ],
    'max_file_size' => '10 MB',
    'max_image_width' => 4096,
    'max_image_height' => 4096,
    'forbidden_filenames' => [
        'shell.php', 'backdoor.php', '.htaccess', 'config.php'
    ],
];

// Ensure directories exist
foreach ([$config['upload_dir'], dirname($config['log_file']), $config['rate_limit_dir']] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Initialize components
$logger = new FileLogger($config['log_file'], LogLevel::INFO);

$storage = new LocalStorage(
    $config['upload_dir'],
    0755,
    0644,
    $config['public_url']
);
$storage->setLogger($logger);

$validator = new ValidationChain();
$validator
    ->addValidator(new FilenameValidator($config['forbidden_filenames']))
    ->addValidator(new ExtensionValidator($config['allowed_extensions']))
    ->addValidator(new MimeTypeValidator($config['allowed_mimes']))
    ->addValidator(new SizeValidator(null, $config['max_file_size']))
    ->addValidator(new ImageDimensionValidator(
        null,
        $config['max_image_width'],
        null,
        $config['max_image_height']
    ));
$validator->setLogger($logger);

$rateLimiter = new FileRateLimiter(
    $config['rate_limit_dir'],
    $config['max_uploads_per_minute'],
    60
);

// Use NullScanner if ClamAV is not available
// In production, configure ClamAvScanner with your ClamAV socket/host
$virusScanner = new NullScanner();
// $virusScanner = new ClamAvScanner('/var/run/clamav/clamd.sock');

$eventDispatcher = new EventDispatcher();
$eventDispatcher->setLogger($logger);

// Register event listeners
$eventDispatcher->addListener(UploadEvents::AFTER_UPLOAD, function (FileEvent $event) use ($logger) {
    $logger->info('File uploaded: {filename}', [
        'filename' => $event->get('filename'),
        'path' => $event->get('path'),
    ]);
});

$eventDispatcher->addListener(UploadEvents::UPLOAD_FAILED, function (FileEvent $event) use ($logger) {
    $logger->warning('Upload failed: {error}', [
        'error' => $event->get('error'),
        'filename' => $event->getFilename(),
    ]);
});

$eventDispatcher->addListener(UploadEvents::RATE_LIMIT_EXCEEDED, function (FileEvent $event) use ($logger) {
    $logger->warning('Rate limit exceeded for {identifier}', [
        'identifier' => $event->get('identifier'),
    ]);
});

// Create upload manager
$uploadManager = new UploadManager(
    $storage,
    $validator,
    $rateLimiter,
    $virusScanner,
    $eventDispatcher
);
$uploadManager->setLogger($logger);
$uploadManager->setHashFilenames(true);

// Handle upload request
$response = ['success' => false, 'message' => '', 'data' => null];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] === UPLOAD_ERR_NO_FILE) {
            throw new \RuntimeException('No file uploaded');
        }

        $file = new File($_FILES['file'], new Utility());
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

        // Upload with rate limiting by IP
        $result = $uploadManager->upload($file, 'user-uploads', $clientIp);

        // Set rate limit headers
        foreach ($result->getRateLimitHeaders() as $header => $value) {
            header("{$header}: {$value}");
        }

        if ($result->isSuccess()) {
            $response = [
                'success' => true,
                'message' => 'File uploaded successfully',
                'data' => [
                    'filename' => $result->getStoredFilename(),
                    'original_name' => $result->getOriginalFilename(),
                    'url' => $result->getPublicUrl(),
                    'size' => $result->getFileSize(),
                    'mime_type' => $result->getMimeType(),
                    'hash' => $result->getFileHash(),
                ],
            ];
        } else {
            http_response_code(400);
            $response = [
                'success' => false,
                'message' => $result->getError(),
                'data' => null,
            ];
        }

    } catch (\Farisc0de\PhpFileUploading\Exception\ValidationException $e) {
        http_response_code($e->getCode() === 1010 ? 429 : 400);
        $response = [
            'success' => false,
            'message' => $e->getMessage(),
            'data' => ['context' => $e->getContext()],
        ];
    } catch (\Exception $e) {
        http_response_code(500);
        $response = [
            'success' => false,
            'message' => 'Upload failed: ' . $e->getMessage(),
            'data' => null,
        ];
    }

    // Return JSON response for AJAX requests
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
        strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode($response);
        exit;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Production File Upload</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .upload-area {
            border: 2px dashed #ddd;
            border-radius: 12px;
            padding: 40px 20px;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
            margin-bottom: 20px;
        }
        .upload-area:hover, .upload-area.dragover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        .upload-area svg {
            width: 48px;
            height: 48px;
            color: #667eea;
            margin-bottom: 15px;
        }
        .upload-area p {
            color: #666;
            margin-bottom: 10px;
        }
        .upload-area .formats {
            font-size: 12px;
            color: #999;
        }
        input[type="file"] {
            display: none;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px 28px;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            display: block;
        }
        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            display: block;
        }
        .file-info {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            font-size: 14px;
        }
        .file-info p {
            margin: 5px 0;
            color: #555;
        }
        .file-info strong {
            color: #333;
        }
        .progress {
            height: 4px;
            background: #eee;
            border-radius: 2px;
            margin-top: 15px;
            overflow: hidden;
            display: none;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s ease;
        }
        .selected-file {
            background: #f0f4ff;
            border-radius: 8px;
            padding: 12px;
            margin-top: 15px;
            display: none;
            align-items: center;
            gap: 10px;
        }
        .selected-file.show {
            display: flex;
        }
        .selected-file .name {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            color: #333;
        }
        .selected-file .size {
            color: #666;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure File Upload</h1>
        <p class="subtitle">Production-ready with validation, rate limiting & virus scanning</p>

        <?php if ($response['success']): ?>
            <div class="message success">
                <?= htmlspecialchars($response['message']) ?>
            </div>
            <?php if ($response['data']): ?>
            <div class="file-info">
                <p><strong>Filename:</strong> <?= htmlspecialchars($response['data']['filename']) ?></p>
                <p><strong>Original:</strong> <?= htmlspecialchars($response['data']['original_name']) ?></p>
                <p><strong>Size:</strong> <?= number_format($response['data']['size']) ?> bytes</p>
                <p><strong>Type:</strong> <?= htmlspecialchars($response['data']['mime_type']) ?></p>
                <?php if ($response['data']['url']): ?>
                <p><strong>URL:</strong> <a href="<?= htmlspecialchars($response['data']['url']) ?>" target="_blank">View File</a></p>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        <?php elseif ($response['message']): ?>
            <div class="message error">
                <?= htmlspecialchars($response['message']) ?>
            </div>
        <?php endif; ?>

        <form method="post" enctype="multipart/form-data" id="uploadForm">
            <div class="upload-area" id="dropZone">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                <p>Drag & drop your file here or click to browse</p>
                <span class="formats">Allowed: JPG, PNG, GIF, PDF, DOC, DOCX (max 10MB)</span>
                <input type="file" name="file" id="fileInput" accept=".jpg,.jpeg,.png,.gif,.pdf,.doc,.docx">
            </div>

            <div class="selected-file" id="selectedFile">
                <span class="name" id="fileName"></span>
                <span class="size" id="fileSize"></span>
            </div>

            <div class="progress" id="progress">
                <div class="progress-bar" id="progressBar"></div>
            </div>

            <button type="submit" class="btn" id="submitBtn">Upload File</button>
        </form>
    </div>

    <script>
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const selectedFile = document.getElementById('selectedFile');
        const fileName = document.getElementById('fileName');
        const fileSize = document.getElementById('fileSize');
        const form = document.getElementById('uploadForm');
        const progress = document.getElementById('progress');
        const progressBar = document.getElementById('progressBar');
        const submitBtn = document.getElementById('submitBtn');

        // Click to upload
        dropZone.addEventListener('click', () => fileInput.click());

        // Drag and drop
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateSelectedFile();
            }
        });

        // File selection
        fileInput.addEventListener('change', updateSelectedFile);

        function updateSelectedFile() {
            if (fileInput.files.length) {
                const file = fileInput.files[0];
                fileName.textContent = file.name;
                fileSize.textContent = formatBytes(file.size);
                selectedFile.classList.add('show');
            } else {
                selectedFile.classList.remove('show');
            }
        }

        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Form submission with progress
        form.addEventListener('submit', function(e) {
            if (!fileInput.files.length) {
                e.preventDefault();
                alert('Please select a file');
                return;
            }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Uploading...';
            progress.style.display = 'block';

            // For non-AJAX submission, just let the form submit
            // For AJAX, you could use XMLHttpRequest or fetch with progress
        });
    </script>
</body>
</html>
