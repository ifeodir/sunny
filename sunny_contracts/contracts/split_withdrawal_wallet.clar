;; Split Withdrawal Wallet Contract
;; Allows withdrawing funds split between multiple addresses

;; Error constants
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_SPLIT (err u101))
(define-constant ERR_INSUFFICIENT_BALANCE (err u102))
(define-constant ERR_TRANSFER_FAILED (err u103))
(define-constant ERR_INVALID_PERCENTAGE (err u104))
(define-constant ERR_PERCENTAGE_SUM_INVALID (err u105))

;; Contract owner
(define-data-var contract-owner principal tx-sender)

;; Split configuration: maps recipient to their percentage (basis points, 0-10000)
;; 10000 = 100%, 5000 = 50%, 2500 = 25%, etc.
(define-map split-config principal uint)

;; List of current recipients
(define-data-var recipients (list 10 principal) (list))

;; Events
(define-data-var total-withdrawn uint u0)

;; Read-only functions

;; Get contract owner
(define-read-only (get-owner)
  (var-get contract-owner))

;; Get contract balance
(define-read-only (get-balance)
  (stx-get-balance (as-contract tx-sender)))

;; Get split percentage for a recipient (in basis points)
(define-read-only (get-split-percentage (recipient principal))
  (default-to u0 (map-get? split-config recipient)))

;; Get all recipients
(define-read-only (get-recipients)
  (var-get recipients))

;; Get total amount withdrawn
(define-read-only (get-total-withdrawn)
  (var-get total-withdrawn))

;; Validate that percentages sum to 10000 (100%)
(define-read-only (validate-percentages)
  (let ((current-recipients (var-get recipients)))
    (fold check-percentage-sum current-recipients u0)))

(define-private (check-percentage-sum (recipient principal) (sum uint))
  (+ sum (get-split-percentage recipient)))

;; Private functions

;; Check if caller is owner
(define-private (is-owner)
  (is-eq tx-sender (var-get contract-owner)))

;; Transfer funds to a recipient
(define-private (transfer-to-recipient (recipient principal) (amount uint))
  (if (> amount u0)
    (as-contract (stx-transfer? amount tx-sender recipient))
    (ok true)))

;; Calculate amount for recipient based on percentage
(define-private (calculate-recipient-amount (total-amount uint) (percentage uint))
  (/ (* total-amount percentage) u10000))

;; Distribute funds to a single recipient
(define-private (distribute-to-recipient (recipient principal) (total-amount uint))
  (let ((percentage (get-split-percentage recipient))
        (amount (calculate-recipient-amount total-amount percentage)))
    (if (> amount u0)
      (transfer-to-recipient recipient amount)
      (ok true))))

;; Public functions

;; Deposit STX to the contract (anyone can deposit)
(define-public (deposit (amount uint))
  (stx-transfer? amount tx-sender (as-contract tx-sender)))

;; Set split configuration (only owner)
(define-public (set-split-config (new-recipients (list 10 principal)) (percentages (list 10 uint)))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (asserts! (is-eq (len new-recipients) (len percentages)) ERR_INVALID_SPLIT)
    
    ;; Clear existing configuration
    (map clear-recipient-config (var-get recipients))
    
    ;; Set new configuration
    (map set-recipient-percentage new-recipients percentages)
    (var-set recipients new-recipients)
    
    ;; Validate that percentages sum to 100%
    (asserts! (is-eq (validate-percentages) u10000) ERR_PERCENTAGE_SUM_INVALID)
    
    (ok true)))

;; Helper function to clear recipient config
(define-private (clear-recipient-config (recipient principal))
  (map-delete split-config recipient))

;; Helper function to set recipient percentage
(define-private (set-recipient-percentage (recipient principal) (percentage uint))
  (begin
    (asserts! (<= percentage u10000) ERR_INVALID_PERCENTAGE)
    (map-set split-config recipient percentage)
    (ok true)))

;; Withdraw and split funds among configured recipients
(define-public (withdraw-split (amount uint))
  (let ((contract-balance (get-balance))
        (current-recipients (var-get recipients)))
    (begin
      ;; Validate withdrawal
      (asserts! (> (len current-recipients) u0) ERR_INVALID_SPLIT)
      (asserts! (<= amount contract-balance) ERR_INSUFFICIENT_BALANCE)
      (asserts! (is-eq (validate-percentages) u10000) ERR_PERCENTAGE_SUM_INVALID)
      
      ;; Distribute to each recipient
      (try! (fold distribute-and-check current-recipients (ok amount)))
      
      ;; Update total withdrawn
      (var-set total-withdrawn (+ (var-get total-withdrawn) amount))
      
      (ok amount))))

;; Helper function for withdrawal distribution
(define-private (distribute-and-check (recipient principal) (result (response uint uint)))
  (match result
    success-amount (begin
      (try! (distribute-to-recipient recipient success-amount))
      (ok success-amount))
    error-code (err error-code)))

;; Withdraw all available funds and split
(define-public (withdraw-all)
  (let ((balance (get-balance)))
    (if (> balance u0)
      (withdraw-split balance)
      (ok u0))))

;; Emergency withdrawal (only owner, bypasses split)
(define-public (emergency-withdraw (amount uint) (recipient principal))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (asserts! (<= amount (get-balance)) ERR_INSUFFICIENT_BALANCE)
    (try! (as-contract (stx-transfer? amount tx-sender recipient)))
    (var-set total-withdrawn (+ (var-get total-withdrawn) amount))
    (ok amount)))

;; Transfer ownership
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (var-set contract-owner new-owner)
    (ok true)))

;; Example usage setup function (for demonstration)
(define-public (setup-50-50-split (recipient1 principal) (recipient2 principal))
  (begin
    (asserts! (is-owner) ERR_UNAUTHORIZED)
    (try! (set-split-config 
           (list recipient1 recipient2) 
           (list u5000 u5000))) ;; 50% each
    (ok true)))