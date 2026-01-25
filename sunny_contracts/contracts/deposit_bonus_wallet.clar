;; Deposit Bonus Wallet Smart Contract
;; Rewards users with bonus tokens when they make deposits

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-OWNER-ONLY (err u100))
(define-constant ERR-INSUFFICIENT-FUNDS (err u101))
(define-constant ERR-INVALID-AMOUNT (err u102))
(define-constant ERR-TRANSFER-FAILED (err u103))

;; Bonus rate: 10% bonus (10 basis points out of 10000)
(define-constant BONUS-RATE u1000)
(define-constant BASIS-POINTS u10000)

;; Data Variables
(define-data-var contract-active bool true)
(define-data-var total-deposits uint u0)
(define-data-var total-bonus-minted uint u0)

;; Data Maps
(define-map user-deposits principal uint)
(define-map user-bonus-balance principal uint)

;; Define the bonus token
(define-fungible-token bonus-token)

;; Read-only functions
(define-read-only (get-user-deposit (user principal))
  (default-to u0 (map-get? user-deposits user))
)

(define-read-only (get-user-bonus-balance (user principal))
  (default-to u0 (map-get? user-bonus-balance user))
)

(define-read-only (get-total-deposits)
  (var-get total-deposits)
)

(define-read-only (get-total-bonus-minted)
  (var-get total-bonus-minted)
)

(define-read-only (calculate-bonus (amount uint))
  (/ (* amount BONUS-RATE) BASIS-POINTS)
)

(define-read-only (is-contract-active)
  (var-get contract-active)
)

;; Private functions
(define-private (update-user-deposit (user principal) (amount uint))
  (let ((current-deposit (get-user-deposit user)))
    (map-set user-deposits user (+ current-deposit amount))
  )
)

(define-private (mint-bonus-tokens (user principal) (amount uint))
  (let ((bonus-amount (calculate-bonus amount)))
    (if (> bonus-amount u0)
      (begin
        ;; Mint bonus tokens to user
        (try! (ft-mint? bonus-token bonus-amount user))
        
        ;; Update user's bonus balance
        (let ((current-bonus (get-user-bonus-balance user)))
          (map-set user-bonus-balance user (+ current-bonus bonus-amount))
        )
        
        ;; Update total bonus minted
        (var-set total-bonus-minted (+ (var-get total-bonus-minted) bonus-amount))
        
        (ok bonus-amount)
      )
      (ok u0)
    )
  )
)

;; Public functions
(define-public (deposit (amount uint))
  (begin
    ;; Check if contract is active
    (asserts! (var-get contract-active) ERR-OWNER-ONLY)
    
    ;; Check for valid amount
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    
    ;; Transfer STX from user to contract
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    
    ;; Update user's deposit record
    (update-user-deposit tx-sender amount)
    
    ;; Update total deposits
    (var-set total-deposits (+ (var-get total-deposits) amount))
    
    ;; Mint bonus tokens
    (let ((bonus-minted (try! (mint-bonus-tokens tx-sender amount))))
      (ok {
        deposit-amount: amount,
        bonus-minted: bonus-minted,
        user: tx-sender
      })
    )
  )
)

(define-public (withdraw-bonus (amount uint))
  (let ((user-balance (get-user-bonus-balance tx-sender)))
    ;; Check if user has sufficient bonus balance
    (asserts! (>= user-balance amount) ERR-INSUFFICIENT-FUNDS)
    
    ;; Burn bonus tokens from user
    (try! (ft-burn? bonus-token amount tx-sender))
    
    ;; Update user's bonus balance
    (map-set user-bonus-balance tx-sender (- user-balance amount))
    
    (ok amount)
  )
)

(define-public (get-bonus-token-balance (user principal))
  (ok (ft-get-balance bonus-token user))
)

;; Admin functions (only contract owner)
(define-public (toggle-contract-active)
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-OWNER-ONLY)
    (var-set contract-active (not (var-get contract-active)))
    (ok (var-get contract-active))
  )
)

(define-public (emergency-withdraw (amount uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-OWNER-ONLY)
    (try! (as-contract (stx-transfer? amount tx-sender CONTRACT-OWNER)))
    (ok amount)
  )
)

;; Contract initialization
(begin
  ;; Set initial contract state
  (var-set contract-active true)
)