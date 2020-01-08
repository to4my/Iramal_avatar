require 'openssl'

# Проверка формата электронной почты пользователя
# Проверка максимальной длины юзернейма пользователя (не больше 40 символов)
# Проверка формата юзернейма пользователя (только латинские буквы, цифры, и знак _)

class User < ApplicationRecord
  ITERATIONS = 20_000
  DIGEST = OpenSSL::Digest::SHA256.new
  EMAIL_PATTERN = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z]+)*\.[a-z]+\z/i

  attr_accessor :password, :email

  has_many :questions

  validates :email, :username, presence: true
  validates :email, :username, uniqueness: true

  validates_presence_of :password, on: create
  validates_confirmation_of :password

  before_validation :verify_email
  before_save :encrypt_password

  def verify_email
    if self.email =~ EMAIL_PATTERN
      self.email = email
    else
      self.email = nil
    end
  end

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
