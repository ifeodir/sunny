;; AuditLog Smart Contract
;; Purpose: Track all file and contract interactions with immutable audit trails

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u401))
(define-constant ERR_INVALID_ACTION (err u402))
(define-constant ERR_LOG_NOT_FOUND (err u404))
(define-constant ERR_INVALID_INPUT (err u400))
(define-constant ERR_INVALID_FILE_ID (err u403))
(define-constant ERR_INVALID_METADATA (err u405))
(define-constant ERR_INVALID_AMOUNT (err u406))

;; Maximum allowed values for security
(define-constant MAX_FILE_ID_LENGTH u64)
(define-constant MAX_METADATA_LENGTH u256)
(define-constant MAX_AMOUNT u1000000000000) ;; 1 trillion micro-STX
(define-constant MAX_QUERY_COUNT u10)

;; Data Variables
(define-data-var log-counter uint u0)

;; Action types for different operations
(define-constant ACTION_UPLOAD u1)
(define-constant ACTION_DOWNLOAD u2)
(define-constant ACTION_PAYMENT u3)
(define-constant ACTION_PERMISSION_CHANGE u4)
(define-constant ACTION_DELETE u5)
(define-constant ACTION_SHARE u6)

;; Audit log entry structure
(define-map audit-logs
    { log-id: uint }
    {
        user: principal,
        action-type: uint,
        file-id: (string-ascii 64),
        target-user: (optional principal),
        amount: (optional uint),
        metadata: (string-utf8 256),
        block-height: uint,
        timestamp: uint
    }
)

;; User activity tracking
(define-map user-log-count
    { user: principal }
    { count: uint }
)

;; File activity tracking
(define-map file-log-count
    { file-id: (string-ascii 64) }
    { count: uint }
)

;; User logs index (for efficient querying)
(define-map user-logs
    { user: principal, index: uint }
    { log-id: uint }
)

;; File logs index (for efficient querying)
(define-map file-logs
    { file-id: (string-ascii 64), index: uint }
    { log-id: uint }
)

;; Input validation functions
(define-private (validate-file-id (file-id (string-ascii 64)))
    (and 
        (> (len file-id) u0)
        (<= (len file-id) MAX_FILE_ID_LENGTH)
    )
)

(define-private (validate-metadata (metadata (string-utf8 256)))
    (<= (len metadata) MAX_METADATA_LENGTH)
)

(define-private (validate-amount (amount uint))
    (and (> amount u0) (<= amount MAX_AMOUNT))
)

(define-private (validate-query-count (count uint))
    (and (> count u0) (<= count MAX_QUERY_COUNT))
)

(define-private (validate-log-id (log-id uint))
    (and (> log-id u0) (<= log-id (var-get log-counter)))
)

(define-private (validate-index (index uint) (max-count uint))
    (< index max-count)
)
(define-private (get-current-timestamp)
    block-height
)

;; Helper function to increment log counter
(define-private (increment-log-counter)
    (let ((current-count (var-get log-counter)))
        (var-set log-counter (+ current-count u1))
        (+ current-count u1)
    )
)

;; Helper function to update user log count
(define-private (update-user-log-count (user principal))
    (let ((current-count (default-to u0 (get count (map-get? user-log-count { user: user })))))
        (map-set user-log-count { user: user } { count: (+ current-count u1) })
        current-count
    )
)

;; Helper function to update file log count
(define-private (update-file-log-count (file-id (string-ascii 64)))
    (let ((current-count (default-to u0 (get count (map-get? file-log-count { file-id: file-id })))))
        (map-set file-log-count { file-id: file-id } { count: (+ current-count u1) })
        current-count
    )
)

;; Core function to create audit log entry
(define-private (create-log-entry 
    (user principal)
    (action-type uint)
    (file-id (string-ascii 64))
    (target-user (optional principal))
    (amount (optional uint))
    (metadata (string-utf8 256))
)
    (let (
        (log-id (increment-log-counter))
        (user-index (update-user-log-count user))
        (file-index (update-file-log-count file-id))
        (current-time (get-current-timestamp))
    )
        ;; Create the main log entry
        (map-set audit-logs
            { log-id: log-id }
            {
                user: user,
                action-type: action-type,
                file-id: file-id,
                target-user: target-user,
                amount: amount,
                metadata: metadata,
                block-height: block-height,
                timestamp: current-time
            }
        )
        
        ;; Create user index entry
        (map-set user-logs
            { user: user, index: user-index }
            { log-id: log-id }
        )
        
        ;; Create file index entry
        (map-set file-logs
            { file-id: file-id, index: file-index }
            { log-id: log-id }
        )
        
        log-id
    )
)

;; Public function to log file upload (with validation)
(define-public (log-upload 
    (file-id (string-ascii 64))
    (metadata (string-utf8 256))
)
    (begin
        (asserts! (validate-file-id file-id) ERR_INVALID_FILE_ID)
        (asserts! (validate-metadata metadata) ERR_INVALID_METADATA)
        (ok (create-log-entry 
            tx-sender 
            ACTION_UPLOAD 
            file-id 
            none 
            none 
            metadata
        ))
    )
)

;; Public function to log file download (with validation)
(define-public (log-download 
    (file-id (string-ascii 64))
    (metadata (string-utf8 256))
)
    (begin
        (asserts! (validate-file-id file-id) ERR_INVALID_FILE_ID)
        (asserts! (validate-metadata metadata) ERR_INVALID_METADATA)
        (ok (create-log-entry 
            tx-sender 
            ACTION_DOWNLOAD 
            file-id 
            none 
            none 
            metadata
        ))
    )
)

;; Public function to log payment (with validation)
(define-public (log-payment 
    (file-id (string-ascii 64))
    (amount uint)
    (target-user principal)
    (metadata (string-utf8 256))
)
    (begin
        (asserts! (validate-file-id file-id) ERR_INVALID_FILE_ID)
        (asserts! (validate-amount amount) ERR_INVALID_AMOUNT)
        (asserts! (validate-metadata metadata) ERR_INVALID_METADATA)
        (asserts! (not (is-eq target-user tx-sender)) ERR_INVALID_INPUT)
        (ok (create-log-entry 
            tx-sender 
            ACTION_PAYMENT 
            file-id 
            (some target-user) 
            (some amount) 
            metadata
        ))
    )
)

;; Public function to log permission change (with validation)
(define-public (log-permission-change 
    (file-id (string-ascii 64))
    (target-user principal)
    (metadata (string-utf8 256))
)
    (begin
        (asserts! (validate-file-id file-id) ERR_INVALID_FILE_ID)
        (asserts! (validate-metadata metadata) ERR_INVALID_METADATA)
        (asserts! (not (is-eq target-user tx-sender)) ERR_INVALID_INPUT)
        (ok (create-log-entry 
            tx-sender 
            ACTION_PERMISSION_CHANGE 
            file-id 
            (some target-user) 
            none 
            metadata
        ))
    )
)

;; Public function to log file deletion (with validation)
(define-public (log-delete 
    (file-id (string-ascii 64))
    (metadata (string-utf8 256))
)
    (begin
        (asserts! (validate-file-id file-id) ERR_INVALID_FILE_ID)
        (asserts! (validate-metadata metadata) ERR_INVALID_METADATA)
        (ok (create-log-entry 
            tx-sender 
            ACTION_DELETE 
            file-id 
            none 
            none 
            metadata
        ))
    )
)

;; Public function to log file sharing (with validation)
(define-public (log-share 
    (file-id (string-ascii 64))
    (target-user principal)
    (metadata (string-utf8 256))
)
    (begin
        (asserts! (validate-file-id file-id) ERR_INVALID_FILE_ID)
        (asserts! (validate-metadata metadata) ERR_INVALID_METADATA)
        (asserts! (not (is-eq target-user tx-sender)) ERR_INVALID_INPUT)
        (ok (create-log-entry 
            tx-sender 
            ACTION_SHARE 
            file-id 
            (some target-user) 
            none 
            metadata
        ))
    )
)

;; Read-only function to get log entry by ID (with validation)
(define-read-only (get-log-entry (log-id uint))
    (if (validate-log-id log-id)
        (map-get? audit-logs { log-id: log-id })
        none
    )
)

;; Read-only function to get user's log entry by index (with validation)
(define-read-only (get-user-log-by-index (user principal) (index uint))
    (let ((user-count (get-user-log-count user)))
        (if (validate-index index user-count)
            (match (map-get? user-logs { user: user, index: index })
                user-log-entry (map-get? audit-logs { log-id: (get log-id user-log-entry) })
                none
            )
            none
        )
    )
)

;; Read-only function to get file's log entry by index (with validation)
(define-read-only (get-file-log-by-index (file-id (string-ascii 64)) (index uint))
    (if (validate-file-id file-id)
        (let ((file-count (get-file-log-count file-id)))
            (if (validate-index index file-count)
                (match (map-get? file-logs { file-id: file-id, index: index })
                    file-log-entry (map-get? audit-logs { log-id: (get log-id file-log-entry) })
                    none
                )
                none
            )
        )
        none
    )
)

;; Read-only function to get user's total log count
(define-read-only (get-user-log-count (user principal))
    (default-to u0 (get count (map-get? user-log-count { user: user })))
)

;; Read-only function to get file's total log count
(define-read-only (get-file-log-count (file-id (string-ascii 64)))
    (default-to u0 (get count (map-get? file-log-count { file-id: file-id })))
)

;; Read-only function to get total log count
(define-read-only (get-total-log-count)
    (var-get log-counter)
)

;; Read-only function to get recent logs (last N entries by providing specific IDs)
(define-read-only (get-recent-logs (count uint))
    (let ((total-logs (var-get log-counter)))
        (if (or (is-eq total-logs u0) (> count total-logs))
            (list)
            (if (<= count u10)
                (get-last-10-logs total-logs count)
                (list) ;; For counts > 10, return empty list (can be extended)
            )
        )
    )
)

;; Helper to get last 10 logs (Clarity-friendly approach)
(define-private (get-last-10-logs (total-logs uint) (count uint))
    (let ((start-id (if (> total-logs count) (+ (- total-logs count) u1) u1)))
        (if (is-eq count u1)
            (list (get-log-entry total-logs))
            (if (is-eq count u2)
                (list (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                (if (is-eq count u3)
                    (list (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                    (if (is-eq count u4)
                        (list (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                        (if (is-eq count u5)
                            (list (get-log-entry (- total-logs u4)) (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                            (if (<= count u10)
                                (get-up-to-10-logs total-logs count)
                                (list)
                            )
                        )
                    )
                )
            )
        )
    )
)

;; Helper for up to 10 logs
(define-private (get-up-to-10-logs (total-logs uint) (count uint))
    (if (is-eq count u6)
        (list (get-log-entry (- total-logs u5)) (get-log-entry (- total-logs u4)) (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
        (if (is-eq count u7)
            (list (get-log-entry (- total-logs u6)) (get-log-entry (- total-logs u5)) (get-log-entry (- total-logs u4)) (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
            (if (is-eq count u8)
                (list (get-log-entry (- total-logs u7)) (get-log-entry (- total-logs u6)) (get-log-entry (- total-logs u5)) (get-log-entry (- total-logs u4)) (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                (if (is-eq count u9)
                    (list (get-log-entry (- total-logs u8)) (get-log-entry (- total-logs u7)) (get-log-entry (- total-logs u6)) (get-log-entry (- total-logs u5)) (get-log-entry (- total-logs u4)) (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                    (list (get-log-entry (- total-logs u9)) (get-log-entry (- total-logs u8)) (get-log-entry (- total-logs u7)) (get-log-entry (- total-logs u6)) (get-log-entry (- total-logs u5)) (get-log-entry (- total-logs u4)) (get-log-entry (- total-logs u3)) (get-log-entry (- total-logs u2)) (get-log-entry (- total-logs u1)) (get-log-entry total-logs))
                )
            )
        )
    )
)

;; Read-only function to get a batch of logs by IDs
(define-read-only (get-logs-by-ids (log-ids (list 10 uint)))
    (map get-log-entry log-ids)
)

;; Read-only function to get multiple user logs (up to 5)
(define-read-only (get-multiple-user-logs (user principal) (index1 uint) (index2 uint) (index3 uint) (index4 uint) (index5 uint))
    (list 
        (get-user-log-by-index user index1)
        (get-user-log-by-index user index2)
        (get-user-log-by-index user index3)
        (get-user-log-by-index user index4)
        (get-user-log-by-index user index5)
    )
)

;; Read-only function to get multiple file logs (up to 5)
(define-read-only (get-multiple-file-logs (file-id (string-ascii 64)) (index1 uint) (index2 uint) (index3 uint) (index4 uint) (index5 uint))
    (list 
        (get-file-log-by-index file-id index1)
        (get-file-log-by-index file-id index2)
        (get-file-log-by-index file-id index3)
        (get-file-log-by-index file-id index4)
        (get-file-log-by-index file-id index5)
    )
)

;; Read-only function to get multiple logs by IDs
(define-read-only (get-multiple-logs (id1 uint) (id2 uint) (id3 uint) (id4 uint) (id5 uint))
    (list 
        (get-log-entry id1)
        (get-log-entry id2)
        (get-log-entry id3)
        (get-log-entry id4)
        (get-log-entry id5)
    )
)

;; Read-only function to check if action type is valid
(define-read-only (is-valid-action-type (action-type uint))
    (or 
        (is-eq action-type ACTION_UPLOAD)
        (or 
            (is-eq action-type ACTION_DOWNLOAD)
            (or 
                (is-eq action-type ACTION_PAYMENT)
                (or 
                    (is-eq action-type ACTION_PERMISSION_CHANGE)
                    (or 
                        (is-eq action-type ACTION_DELETE)
                        (is-eq action-type ACTION_SHARE)
                    )
                )
            )
        )
    )
)

;; Read-only function to get action type name
(define-read-only (get-action-type-name (action-type uint))
    (if (is-eq action-type ACTION_UPLOAD)
        "UPLOAD"
        (if (is-eq action-type ACTION_DOWNLOAD)
            "DOWNLOAD"
            (if (is-eq action-type ACTION_PAYMENT)
                "PAYMENT"
                (if (is-eq action-type ACTION_PERMISSION_CHANGE)
                    "PERMISSION_CHANGE"
                    (if (is-eq action-type ACTION_DELETE)
                        "DELETE"
                        (if (is-eq action-type ACTION_SHARE)
                            "SHARE"
                            "UNKNOWN"
                        )
                    )
                )
            )
        )
    )
)