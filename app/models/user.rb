require 'openssl'

class User < ApplicationRecord
  ITERATIONS = 20_000
  DIGEST = OpenSSL::Digest::SHA256.new
  USERNAME_PATTERN = /[a-zA-Z0-9\\_\\"]+$/.freeze

  attr_accessor :password, :email

  has_many :questions

  validates :email, :username, presence: true
  validates :email, :username, uniqueness: true
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, length: { maximum: 40 }, format: { with: USERNAME_PATTERN }

  validates :password, presence: true, confirmation: true, on: create

  before_save :encrypt_password

  def encrypt_password
    if self.password.present?
      self.password_salt = User.hash_to_string(OpenSSL::Random.random_bytes(16))
      self.password_hash = User.hash_to_string(
        OpenSSL::PKCS5.pbkdf2_hmac(
          self.password, self.password_salt, ITERATIONS, DIGEST.length, DIGEST
        )
      )
    end
  end

  def self.hash_to_string(password_hash)
    password_hash.unpack('H*')[0]
  end

  def self.authenticate(email, password)
    user = find_by(email: email)

    if user.present? &&
       user.password_hash == User.hash_to_string(
         OpenSSL::PKCS5.pbkdf2_hmac(
           password, user.password_salt, ITERATIONS, DIGEST.length, DIGEST
         )
       )
      user
    else
      nil
    end
  end
end
