class Question < ApplicationRecord
  # Проверка максимальной длины текста вопроса (максимум 255 символов)

  belongs_to :user

  validates :text, :user, presence: true
  # on: create
  # on: update
end
